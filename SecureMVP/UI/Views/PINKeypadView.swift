import SwiftUI

/// Reusable numeric keypad for PIN entry
struct PINKeypadView: View {
    let onNumberTap: (Int) -> Void
    let onDeleteTap: () -> Void

    private let numbers = [
        [1, 2, 3],
        [4, 5, 6],
        [7, 8, 9],
        [-1, 0, -2]  // -1 = empty, -2 = delete
    ]

    var body: some View {
        VStack(spacing: 15) {
            ForEach(numbers, id: \.self) { row in
                HStack(spacing: 15) {
                    ForEach(row, id: \.self) { number in
                        keypadButton(for: number)
                    }
                }
            }
        }
        .padding()
    }

    @ViewBuilder
    private func keypadButton(for number: Int) -> some View {
        Button(action: {
            if number >= 0 && number <= 9 {
                onNumberTap(number)
            } else if number == -2 {
                onDeleteTap()
            }
        }) {
            ZStack {
                if number == -1 {
                    // Empty space
                    Color.clear
                        .frame(width: 80, height: 80)
                } else if number == -2 {
                    // Delete button
                    Circle()
                        .fill(Color.gray.opacity(0.2))
                        .frame(width: 80, height: 80)
                        .overlay(
                            Image(systemName: "delete.left")
                                .font(.title2)
                                .foregroundColor(.primary)
                        )
                } else {
                    // Number button
                    Circle()
                        .fill(Color.gray.opacity(0.2))
                        .frame(width: 80, height: 80)
                        .overlay(
                            Text("\(number)")
                                .font(.title)
                                .foregroundColor(.primary)
                        )
                }
            }
        }
        .buttonStyle(PlainButtonStyle())
        .disabled(number == -1)
    }
}

// MARK: - Preview

#Preview {
    VStack {
        Spacer()

        PINKeypadView(
            onNumberTap: { number in
                print("Tapped: \(number)")
            },
            onDeleteTap: {
                print("Delete tapped")
            }
        )

        Spacer()
    }
}
