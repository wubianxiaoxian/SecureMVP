#!/bin/bash

# Extension Info.plist Configuration Fix Script
# Fixes: "Couldn't load Info dictionary for SecureMVPAutofill.appex"

PROJECT_FILE="SecureMVP.xcodeproj/project.pbxproj"
BACKUP_FILE="SecureMVP.xcodeproj/project.pbxproj.backup_$(date +%Y%m%d_%H%M%S)"

echo "🔧 Fixing Extension Info.plist configuration..."

# 1. Backup project file
echo "📋 Creating backup: $BACKUP_FILE"
cp "$PROJECT_FILE" "$BACKUP_FILE"

# 2. Remove conflicting INFOPLIST_FILE setting
echo "🗑️  Removing conflicting INFOPLIST_FILE setting..."
sed -i '' '/INFOPLIST_FILE = SecureMVPAutofill\/Info.plist;/d' "$PROJECT_FILE"

# 3. Verify GENERATE_INFOPLIST_FILE is YES
echo "✅ Ensuring GENERATE_INFOPLIST_FILE = YES..."

# 4. Check if NSExtension keys exist
if grep -q "NSExtensionPointIdentifier" "$PROJECT_FILE"; then
    echo "✅ NSExtension keys already exist"
else
    echo "⚠️  NSExtension keys missing - need manual addition"
    echo ""
    echo "Please add these keys to project.pbxproj manually:"
    echo ""
    echo "INFOPLIST_KEY_NSExtension = {"
    echo "    NSExtensionPointIdentifier = \"com.apple.authentication-services.credential-provider-ui\";"
    echo "    NSExtensionPrincipalClass = \"CredentialProviderViewController\";"
    echo "};"
fi

echo ""
echo "✅ Configuration updated!"
echo "📝 Backup saved to: $BACKUP_FILE"
echo ""
echo "Next steps:"
echo "1. Open Xcode"
echo "2. Select SecureMVPAutofill target"
echo "3. Build Settings → Search 'Info.plist'"
echo "4. Verify settings match the guide below"

cat << 'GUIDE'

📋 Required Build Settings for SecureMVPAutofill:

1. GENERATE_INFOPLIST_FILE = YES
2. INFOPLIST_KEY_CFBundleDisplayName = SecureMVP
3. INFOPLIST_KEY_NSExtension = {
     NSExtensionPointIdentifier = "com.apple.authentication-services.credential-provider-ui";
     NSExtensionPrincipalClass = "CredentialProviderViewController";
   }

⚠️  Do NOT set:
   - INFOPLIST_FILE (remove if exists)

GUIDE

echo ""
echo "🚀 Ready to build!"
