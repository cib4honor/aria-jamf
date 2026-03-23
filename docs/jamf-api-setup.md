# Jamf Pro API Role Setup

ARIA connects to Jamf Pro using OAuth client credentials. You need to create an API role and client in Jamf Pro.

## Step 1 — Create an API Role

1. In Jamf Pro go to **Settings → System → API roles and clients**
2. Click the **API Roles** tab → **New**
3. Name the role `ARIA`
4. Grant these privileges:
   - **Read Computers**
   - **Read Computer Check-In**
   - **Read Computer Inventory Collection**
   - **Send Computer Remote Command to Restart** *(for Restart action)*
   - **Send Computer Bluetooth Command** *(optional, for Lock)*
5. Click **Save**

## Step 2 — Create an API Client

1. Click the **API Clients** tab → **New**
2. Name it `ARIA`
3. Assign the `ARIA` role you just created
4. Set **Access Token Lifetime** to `1800` seconds (30 minutes)
5. Click **Save**
6. Click **Generate Client Secret** and copy both the **Client ID** and **Client Secret**

## Step 3 — Add to .env

```env
JAMF_URL=https://yourschool.jamfcloud.com
JAMF_CLIENT_ID=paste-client-id-here
JAMF_CLIENT_SECRET=paste-client-secret-here
```

## Minimum Permissions Note

ARIA only needs read access to computers for device lookups and fleet queries. The restart/lock MDM commands require the additional send command privileges. If you don't want techs to be able to send MDM commands, simply omit those privileges from the role.
