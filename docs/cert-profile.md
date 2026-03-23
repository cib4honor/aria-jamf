# Distributing the ARIA SSL Certificate to Managed Macs

ARIA uses a self-signed SSL certificate. For techs to access ARIA without browser warnings, the certificate needs to be trusted on their Macs. The easiest way to do this at scale is a Jamf configuration profile.

## Step 1 — Export the certificate

After running `python3 setup.py`, your certificate is at `aria-cert.pem` in the ARIA folder.

Convert it to DER format for the config profile:

```bash
openssl x509 -in aria-cert.pem -outform DER -out aria-cert.der
```

## Step 2 — Create a configuration profile in Jamf Pro

1. In Jamf Pro go to **Computers → Configuration Profiles → New**
2. Give it a name: `ARIA Certificate Trust`
3. Click **Certificate** in the left sidebar → **Configure**
4. Upload `aria-cert.der`
5. Set **Certificate Name**: `ARIA Local Certificate`
6. Check **Allow all apps access**

## Step 3 — Scope and deploy

1. Set the scope to your IT tech group or all computers
2. Click **Save**
3. Jamf will push the cert to scoped Macs on next check-in

## Manual trust (single Mac)

If you just need to trust the cert on one Mac without a profile:

1. Open **Keychain Access**
2. Select the **System** keychain
3. Drag `aria-cert.pem` into the keychain
4. Double-click the new certificate → expand **Trust**
5. Set **When using this certificate** to **Always Trust**
6. Close and enter your password to confirm

## Verifying trust

After deploying, open `https://aria.local:5001` in Chrome. You should see the ARIA setup screen with no security warning. If you still see a warning, check that:

- The cert was imported to the **System** keychain (not Login)
- The hostname you're using matches the cert's Subject Alternative Names
- Chrome has been restarted since the cert was trusted
