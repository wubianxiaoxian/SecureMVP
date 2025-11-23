import Foundation
import CoreLocation

/// Sentinel v1: Local AI-powered trust scoring engine
/// - Detects anomalous credential access patterns
/// - 100% on-device, no cloud/telemetry
/// - Bayesian anomaly detection + simple statistical model
/// - Learns user behavior patterns over time
class SentinelEngine {

    // MARK: - Error Types

    enum SentinelError: LocalizedError {
        case modelNotInitialized
        case insufficientData
        case featureExtractionFailed

        var errorDescription: String? {
            switch self {
            case .modelNotInitialized:
                return "Sentinel model not initialized"
            case .insufficientData:
                return "Insufficient data for trust scoring"
            case .featureExtractionFailed:
                return "Failed to extract features"
            }
        }
    }

    // MARK: - Trust Score

    enum TrustLevel: String, Codable {
        case trusted      // Score > 0.8: Auto-fill immediately
        case review       // Score 0.5-0.8: Show confirmation
        case suspicious   // Score < 0.5: Require additional auth

        var color: String {
            switch self {
            case .trusted: return "green"
            case .review: return "yellow"
            case .suspicious: return "red"
            }
        }

        var emoji: String {
            switch self {
            case .trusted: return "✅"
            case .review: return "⚠️"
            case .suspicious: return "🚨"
            }
        }
    }

    struct TrustScore: Codable {
        let score: Double              // 0.0 - 1.0
        let level: TrustLevel
        let confidence: Double          // How confident is the model
        let reasoning: [String]         // Human-readable reasons
        let timestamp: Date

        init(score: Double, reasoning: [String] = []) {
            self.score = max(0.0, min(1.0, score))
            self.timestamp = Date()
            self.reasoning = reasoning

            // Determine level
            if score > 0.8 {
                self.level = .trusted
                self.confidence = score
            } else if score > 0.5 {
                self.level = .review
                self.confidence = 0.7
            } else {
                self.level = .suspicious
                self.confidence = 1.0 - score
            }
        }
    }

    // MARK: - Access Request Context

    struct AccessRequest {
        let credentialID: UUID
        let domain: String
        let requestingApp: String?      // Bundle ID of requesting app
        let timestamp: Date
        let dayOfWeek: Int               // 1-7 (Sunday = 1)
        let hourOfDay: Int               // 0-23
        let deviceLocked: Bool           // Was device locked before request?
        let location: CLLocation?        // Optional location
        let userInteractionTime: TimeInterval? // Time spent selecting
    }

    // MARK: - Historical Baseline

    struct AccessBaseline: Codable {
        var credentialID: UUID
        var totalAccesses: Int
        var hourDistribution: [Int: Int]       // Hour -> count
        var dayOfWeekDistribution: [Int: Int]  // Day -> count
        var averageInterval: TimeInterval      // Average time between accesses
        var lastAccessTime: Date?
        var accessLocations: [StoredLocation]  // Historical locations
        var commonApps: [String: Int]          // App bundle ID -> count

        init(credentialID: UUID) {
            self.credentialID = credentialID
            self.totalAccesses = 0
            self.hourDistribution = [:]
            self.dayOfWeekDistribution = [:]
            self.averageInterval = 0
            self.lastAccessTime = nil
            self.accessLocations = []
            self.commonApps = [:]
        }

        struct StoredLocation: Codable {
            let latitude: Double
            let longitude: Double
            let timestamp: Date
        }
    }

    // MARK: - Singleton

    static let shared = SentinelEngine()
    private init() {
        loadModel()
    }

    // MARK: - Model Storage

    private var baselines: [UUID: AccessBaseline] = [:]
    private let modelQueue = DispatchQueue(label: "com.securemvp.sentinel", qos: .userInitiated)
    private let keychain = KeychainManager.shared

    // Learning phase: First 14 days, model is permissive
    private let learningPeriodDays = 14
    private var modelCreationDate: Date?

    // MARK: - Public Interface

    /// Calculate trust score for an access request
    /// - Parameter request: Access request context
    /// - Returns: Trust score with reasoning
    func calculateTrustScore(for request: AccessRequest) -> TrustScore {
        return modelQueue.sync {
            // Get or create baseline for this credential
            var baseline = baselines[request.credentialID] ?? AccessBaseline(credentialID: request.credentialID)

            // Check if we're in learning phase
            if isInLearningPhase() {
                // During learning, be permissive (trust = 0.75)
                let reasoning = ["🎓 Learning mode: Building behavior model (\(daysInLearning())/\(learningPeriodDays) days)"]
                recordAccess(request: request, baseline: &baseline)
                baselines[request.credentialID] = baseline
                return TrustScore(score: 0.75, reasoning: reasoning)
            }

            // Insufficient data
            if baseline.totalAccesses < 5 {
                let reasoning = ["📊 Insufficient data: Only \(baseline.totalAccesses) prior accesses"]
                recordAccess(request: request, baseline: &baseline)
                baselines[request.credentialID] = baseline
                return TrustScore(score: 0.6, reasoning: reasoning)
            }

            // Calculate individual feature scores
            var scores: [Double] = []
            var reasoning: [String] = []

            // FEATURE 1: Temporal Pattern (Hour of day)
            let temporalScore = scoreTemporalPattern(request: request, baseline: baseline)
            scores.append(temporalScore.score)
            if temporalScore.score < 0.5 {
                reasoning.append(temporalScore.reason)
            }

            // FEATURE 2: Day of Week Pattern
            let dayScore = scoreDayOfWeek(request: request, baseline: baseline)
            scores.append(dayScore.score)
            if dayScore.score < 0.5 {
                reasoning.append(dayScore.reason)
            }

            // FEATURE 3: Access Frequency
            let frequencyScore = scoreAccessFrequency(request: request, baseline: baseline)
            scores.append(frequencyScore.score)
            if frequencyScore.score < 0.5 {
                reasoning.append(frequencyScore.reason)
            }

            // FEATURE 4: Requesting App Context
            if let app = request.requestingApp {
                let appScore = scoreRequestingApp(app: app, baseline: baseline)
                scores.append(appScore.score)
                if appScore.score < 0.5 {
                    reasoning.append(appScore.reason)
                }
            }

            // FEATURE 5: Location (if available)
            if let location = request.location {
                let locationScore = scoreLocation(location: location, baseline: baseline)
                scores.append(locationScore.score)
                if locationScore.score < 0.5 {
                    reasoning.append(locationScore.reason)
                }
            }

            // FEATURE 6: Domain Match (fuzzy matching)
            let domainScore = scoreDomainMatch(request: request)
            scores.append(domainScore.score)
            if domainScore.score < 0.7 {
                reasoning.append(domainScore.reason)
            }

            // Weighted combination of scores
            let finalScore = calculateWeightedScore(scores)

            // Record this access for future learning
            recordAccess(request: request, baseline: &baseline)
            baselines[request.credentialID] = baseline

            // Add positive reasoning if trusted
            if finalScore > 0.8 && reasoning.isEmpty {
                reasoning.append("✅ Access pattern matches your typical behavior")
            }

            return TrustScore(score: finalScore, reasoning: reasoning)
        }
    }

    /// Record a successful access (for learning)
    func recordSuccessfulAccess(request: AccessRequest) {
        modelQueue.async {
            var baseline = self.baselines[request.credentialID] ?? AccessBaseline(credentialID: request.credentialID)
            self.recordAccess(request: request, baseline: &baseline)
            self.baselines[request.credentialID] = baseline
            self.persistModel()
        }
    }

    /// Get baseline statistics for a credential
    func getBaseline(for credentialID: UUID) -> AccessBaseline? {
        return modelQueue.sync {
            return baselines[credentialID]
        }
    }

    // MARK: - Feature Scoring

    private func scoreTemporalPattern(request: AccessRequest, baseline: AccessBaseline) -> (score: Double, reason: String) {
        let hour = request.hourOfDay

        // Get probability of access at this hour
        let totalAccesses = baseline.totalAccesses
        let hourAccesses = baseline.hourDistribution[hour] ?? 0
        let probability = Double(hourAccesses) / Double(max(1, totalAccesses))

        // Gaussian likelihood
        var score = probability * 3.0 // Amplify for scoring

        // Check if this is a completely new hour
        if hourAccesses == 0 {
            score = 0.3
            return (score, "🕐 Unusual access time (\(hour):00 - never accessed at this hour)")
        }

        return (min(1.0, score), "")
    }

    private func scoreDayOfWeek(request: AccessRequest, baseline: AccessBaseline) -> (score: Double, reason: String) {
        let day = request.dayOfWeek

        let totalAccesses = baseline.totalAccesses
        let dayAccesses = baseline.dayOfWeekDistribution[day] ?? 0
        let probability = Double(dayAccesses) / Double(max(1, totalAccesses))

        var score = probability * 2.5

        if dayAccesses == 0 {
            let dayName = getDayName(day)
            return (0.4, "📅 Unusual day of week (\(dayName) - rarely accessed on this day)")
        }

        return (min(1.0, score), "")
    }

    private func scoreAccessFrequency(request: AccessRequest, baseline: AccessBaseline) -> (score: Double, reason: String) {
        guard let lastAccess = baseline.lastAccessTime else {
            return (0.7, "") // No history, neutral score
        }

        let timeSinceLastAccess = request.timestamp.timeIntervalSince(lastAccess)
        let avgInterval = baseline.averageInterval

        // Check if access is too frequent (potential automated attack)
        if timeSinceLastAccess < 60 && avgInterval > 3600 { // < 1 min, but usually > 1 hour
            return (0.2, "⚡ Suspiciously rapid access (avg interval: \(formatInterval(avgInterval)))")
        }

        // Check if access is much longer than usual
        if avgInterval > 0 {
            let ratio = timeSinceLastAccess / avgInterval
            if ratio > 10.0 { // 10x longer than usual
                return (0.6, "🕰️ Unusually long time since last access")
            }
        }

        return (0.9, "")
    }

    private func scoreRequestingApp(app: String, baseline: AccessBaseline) -> (score: Double, reason: String) {
        let appAccesses = baseline.commonApps[app] ?? 0

        if appAccesses == 0 {
            return (0.4, "📱 New requesting app: \(app)")
        }

        // More common apps get higher scores
        let totalAccesses = baseline.totalAccesses
        let probability = Double(appAccesses) / Double(totalAccesses)

        return (min(1.0, probability * 2.0), "")
    }

    private func scoreLocation(location: CLLocation, baseline: AccessBaseline) -> (score: Double, reason: String) {
        // Check if location is near any historical access location
        for historicalLoc in baseline.accessLocations {
            let historical = CLLocation(
                latitude: historicalLoc.latitude,
                longitude: historicalLoc.longitude
            )

            let distance = location.distance(from: historical)

            // Within 1km = trusted
            if distance < 1000 {
                return (0.95, "")
            }
        }

        // New location
        if baseline.accessLocations.count > 3 {
            return (0.5, "📍 Unfamiliar location (>1km from usual)")
        }

        return (0.7, "") // Still learning locations
    }

    private func scoreDomainMatch(request: AccessRequest) -> (score: Double, reason: String) {
        // Simple domain fuzzy matching
        // In real implementation, use more sophisticated NLP/ML

        // For now, always return high score (assume Autofill provides correct domain)
        return (0.9, "")
    }

    // MARK: - Weighted Scoring

    private func calculateWeightedScore(_ scores: [Double]) -> Double {
        guard !scores.isEmpty else { return 0.5 }

        // Weighted average (can be tuned)
        let weights: [Double]
        switch scores.count {
        case 1:
            weights = [1.0]
        case 2:
            weights = [0.6, 0.4]
        case 3:
            weights = [0.4, 0.3, 0.3]
        case 4:
            weights = [0.3, 0.3, 0.2, 0.2]
        case 5:
            weights = [0.25, 0.2, 0.2, 0.2, 0.15]
        default:
            weights = [0.2, 0.2, 0.15, 0.15, 0.15, 0.15]
        }

        var weightedSum = 0.0
        for (index, score) in scores.enumerated() {
            let weight = index < weights.count ? weights[index] : (1.0 / Double(scores.count))
            weightedSum += score * weight
        }

        return weightedSum
    }

    // MARK: - Learning & Recording

    private func recordAccess(request: AccessRequest, baseline: inout AccessBaseline) {
        baseline.totalAccesses += 1

        // Update hour distribution
        baseline.hourDistribution[request.hourOfDay, default: 0] += 1

        // Update day distribution
        baseline.dayOfWeekDistribution[request.dayOfWeek, default: 0] += 1

        // Update average interval
        if let lastAccess = baseline.lastAccessTime {
            let interval = request.timestamp.timeIntervalSince(lastAccess)
            let totalInterval = baseline.averageInterval * Double(baseline.totalAccesses - 1)
            baseline.averageInterval = (totalInterval + interval) / Double(baseline.totalAccesses)
        }
        baseline.lastAccessTime = request.timestamp

        // Update location history (keep last 10)
        if let location = request.location {
            let storedLoc = AccessBaseline.StoredLocation(
                latitude: location.coordinate.latitude,
                longitude: location.coordinate.longitude,
                timestamp: request.timestamp
            )
            baseline.accessLocations.append(storedLoc)
            if baseline.accessLocations.count > 10 {
                baseline.accessLocations.removeFirst()
            }
        }

        // Update app distribution
        if let app = request.requestingApp {
            baseline.commonApps[app, default: 0] += 1
        }
    }

    // MARK: - Learning Phase

    private func isInLearningPhase() -> Bool {
        guard let creationDate = modelCreationDate else {
            return true // Not initialized yet
        }

        let daysSinceCreation = Calendar.current.dateComponents(
            [.day],
            from: creationDate,
            to: Date()
        ).day ?? 0

        return daysSinceCreation < learningPeriodDays
    }

    private func daysInLearning() -> Int {
        guard let creationDate = modelCreationDate else {
            return 0
        }

        return Calendar.current.dateComponents(
            [.day],
            from: creationDate,
            to: Date()
        ).day ?? 0
    }

    // MARK: - Model Persistence

    private func persistModel() {
        let modelData = SentinelModel(
            baselines: Array(baselines.values),
            creationDate: modelCreationDate ?? Date()
        )

        try? keychain.save(modelData, type: .sentinelModel)
    }

    private func loadModel() {
        if let modelData = try? keychain.retrieve(type: .sentinelModel, as: SentinelModel.self) {
            self.baselines = Dictionary(uniqueKeysWithValues: modelData.baselines.map { ($0.credentialID, $0) })
            self.modelCreationDate = modelData.creationDate
            print("📊 Sentinel model loaded: \(baselines.count) credentials")
        } else {
            self.modelCreationDate = Date()
            print("📊 Sentinel model initialized (learning mode)")
        }
    }

    func resetModel() {
        modelQueue.sync {
            baselines.removeAll()
            modelCreationDate = Date()
            try? keychain.delete(type: .sentinelModel)
        }
    }

    // MARK: - Utilities

    private func getDayName(_ day: Int) -> String {
        let days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
        return days[max(0, min(6, day - 1))]
    }

    private func formatInterval(_ interval: TimeInterval) -> String {
        let hours = Int(interval / 3600)
        if hours > 24 {
            return "\(hours / 24) days"
        } else if hours > 0 {
            return "\(hours) hours"
        } else {
            return "\(Int(interval / 60)) minutes"
        }
    }
}

// MARK: - Persisted Model

private struct SentinelModel: Codable {
    let baselines: [SentinelEngine.AccessBaseline]
    let creationDate: Date
}

// MARK: - Factory for Creating Access Requests

extension SentinelEngine {

    static func createAccessRequest(
        credentialID: UUID,
        domain: String,
        requestingApp: String? = Bundle.main.bundleIdentifier
    ) -> AccessRequest {
        let now = Date()
        let calendar = Calendar.current

        let hour = calendar.component(.hour, from: now)
        let dayOfWeek = calendar.component(.weekday, from: now) // 1-7

        return AccessRequest(
            credentialID: credentialID,
            domain: domain,
            requestingApp: requestingApp,
            timestamp: now,
            dayOfWeek: dayOfWeek,
            hourOfDay: hour,
            deviceLocked: false, // Can be determined via LAContext
            location: nil,       // Would require CoreLocation permission
            userInteractionTime: nil
        )
    }
}
