#!/bin/bash

echo "🔍 SecureMVP Autofill Extension Configuration Verification"
echo "=========================================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS="${GREEN}✅ PASS${NC}"
FAIL="${RED}❌ FAIL${NC}"
WARN="${YELLOW}⚠️  WARN${NC}"

APP_PATH="/Users/kent.sun/Library/Developer/Xcode/DerivedData/SecureMVP-fkvxhjcmybebhrfarbybapokismk/Build/Products/Debug-iphoneos/SecureMVP.app"
EXT_PATH="$APP_PATH/PlugIns/SecureMVPAutofill.appex"
INFO_PLIST="$EXT_PATH/Info.plist"

echo "📍 Checking build artifacts..."
echo ""

# 1. Check if extension exists
echo -n "1. Extension .appex exists: "
if [ -d "$EXT_PATH" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
    echo "   Extension not found at: $EXT_PATH"
    exit 1
fi

# 2. Check Info.plist
echo -n "2. Info.plist exists: "
if [ -f "$INFO_PLIST" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
    exit 1
fi

# 3. Check Bundle Identifier
echo -n "3. CFBundleIdentifier: "
BUNDLE_ID=$(plutil -extract CFBundleIdentifier raw "$INFO_PLIST" 2>/dev/null)
if [ "$BUNDLE_ID" = "com.securemvp.app.SecureMVPAutofill" ]; then
    echo -e "$PASS ($BUNDLE_ID)"
else
    echo -e "$FAIL (Got: $BUNDLE_ID, Expected: com.securemvp.app.SecureMVPAutofill)"
fi

# 4. Check NSExtensionPointIdentifier
echo -n "4. NSExtensionPointIdentifier: "
EXT_POINT=$(plutil -extract NSExtension.NSExtensionPointIdentifier raw "$INFO_PLIST" 2>/dev/null)
if [ "$EXT_POINT" = "com.apple.authentication-services.credential-provider-ui" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL (Got: $EXT_POINT)"
fi

# 5. Check NSExtensionPrincipalClass
echo -n "5. NSExtensionPrincipalClass: "
PRINCIPAL_CLASS=$(plutil -extract NSExtension.NSExtensionPrincipalClass raw "$INFO_PLIST" 2>/dev/null)
if [ "$PRINCIPAL_CLASS" = "SecureMVPAutofill.CredentialProviderViewController" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL (Got: $PRINCIPAL_CLASS)"
fi

# 6. Check ProvidesPasswords
echo -n "6. ProvidesPasswords: "
PROVIDES_PASSWORDS=$(plutil -extract NSExtension.NSExtensionAttributes.ASCredentialProviderExtensionCapabilities.ProvidesPasswords raw "$INFO_PLIST" 2>/dev/null)
if [ "$PROVIDES_PASSWORDS" = "true" ] || [ "$PROVIDES_PASSWORDS" = "1" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL (Got: $PROVIDES_PASSWORDS)"
fi

# 7. Check ProvidesPasskeys
echo -n "7. ProvidesPasskeys: "
PROVIDES_PASSKEYS=$(plutil -extract NSExtension.NSExtensionAttributes.ASCredentialProviderExtensionCapabilities.ProvidesPasskeys raw "$INFO_PLIST" 2>/dev/null)
if [ "$PROVIDES_PASSKEYS" = "true" ] || [ "$PROVIDES_PASSKEYS" = "1" ]; then
    echo -e "$PASS"
else
    echo -e "$FAIL (Got: $PROVIDES_PASSKEYS)"
fi

# 8. Check ShowsConfigurationUI (iOS 17+)
echo -n "8. ShowsConfigurationUI: "
SHOWS_CONFIG=$(plutil -extract NSExtension.NSExtensionAttributes.ASCredentialProviderExtensionCapabilities.ShowsConfigurationUI raw "$INFO_PLIST" 2>/dev/null)
if [ "$SHOWS_CONFIG" = "true" ] || [ "$SHOWS_CONFIG" = "1" ]; then
    echo -e "$PASS"
else
    echo -e "$WARN (Got: $SHOWS_CONFIG - May cause issues on iOS 17+)"
fi

# 9. Check ASCredentialProviderExtensionShowsConfigurationUI (iOS <17)
echo -n "9. ASCredentialProviderExtensionShowsConfigurationUI: "
SHOWS_CONFIG_OLD=$(plutil -extract NSExtension.ASCredentialProviderExtensionShowsConfigurationUI raw "$INFO_PLIST" 2>/dev/null)
if [ "$SHOWS_CONFIG_OLD" = "true" ] || [ "$SHOWS_CONFIG_OLD" = "1" ]; then
    echo -e "$PASS"
else
    echo -e "$WARN (Got: $SHOWS_CONFIG_OLD - May cause issues on iOS <17)"
fi

echo ""
echo "🔐 Checking Entitlements..."
echo ""

# 10. Check Extension Entitlements
ENTITLEMENTS=$(codesign -d --entitlements :- "$EXT_PATH" 2>&1 | plutil -p - 2>/dev/null)

echo -n "10. Credential Provider Entitlement: "
if echo "$ENTITLEMENTS" | grep -q "com.apple.developer.authentication-services.autofill-credential-provider"; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
fi

echo -n "11. App Groups: "
if echo "$ENTITLEMENTS" | grep -q "group.com.securemvp.shared"; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
fi

echo -n "12. Keychain Access Groups: "
if echo "$ENTITLEMENTS" | grep -q "com.securemvp.app"; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
fi

echo ""
echo "📦 Checking Code Signature..."
echo ""

echo -n "13. Extension is signed: "
if codesign -v "$EXT_PATH" 2>/dev/null; then
    echo -e "$PASS"
else
    echo -e "$FAIL"
fi

echo ""
echo "📊 Summary"
echo "=========="
echo ""
echo "Extension Path: $EXT_PATH"
echo "Bundle ID: $BUNDLE_ID"
echo "Principal Class: $PRINCIPAL_CLASS"
echo ""

echo "🎯 Next Steps:"
echo ""
echo "1. ⚠️  RESTART YOUR IPHONE (Very Important!)"
echo "   - iOS needs to reindex extensions after installation"
echo ""
echo "2. Check Settings on iPhone:"
echo "   Option A: Settings → Passwords → Autofill Passwords → Other Password Providers"
echo "   Option B: Settings → General → AutoFill & Passwords → AutoFill From"
echo ""
echo "3. Enable SecureMVP if it appears"
echo ""
echo "4. If still not visible after restart:"
echo "   - Check device console logs:"
echo "     open SecureMVP.xcodeproj"
echo "     Window → Devices and Simulators → kentphone → Open Console"
echo "   - Search for: \"extension\" or \"credential provider\""
echo ""

# Check if app is installed on device
echo "📱 Device Check"
echo "==============="
echo ""
DEVICE_ID="00008120-0018454A3ED8A01E"
echo -n "14. App installed on device: "
INSTALLED=$(xcrun devicectl device info apps --device $DEVICE_ID 2>/dev/null | grep "com.securemvp.app" || echo "")
if [ -n "$INSTALLED" ]; then
    echo -e "$PASS"
else
    echo -e "$WARN (Cannot verify - device may not be connected)"
fi

echo ""
echo "✅ Configuration verification complete!"
echo ""
