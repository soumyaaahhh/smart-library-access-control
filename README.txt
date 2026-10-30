SMART LIBRARY ACCESS CONTROL - UPDATED BUILD

INSTALL
1. Extract the ZIP and open this folder in VS Code.
2. In PowerShell run: pip install -r requirements.txt
3. Run: python app.py
4. Open http://127.0.0.1:5000

DEMO ACCOUNTS
Main Admin: admin@library.demo / Admin123!
Librarian: librarian@library.demo / Lib12345!
Student: student@library.demo / Student123!
Faculty: faculty@library.demo / Faculty123!
Demo OTP: 246810

ROLE BOUNDARIES
Student: browse, view and download permitted books/papers only. No uploads or resource management.
Faculty: browse, view/download permitted resources and upload course notes/papers.
Librarian: add books and manage library catalogue resources.
Main Admin: manage accounts, access settings, risk weights, simulator and security logs. Admin cannot browse or manage library resources.

RISK SIGNALS (only evaluated after ABAC passes)
- New/unrecognized browser token: +20
- Unfamiliar location: +25 when user has saved a usual location and current browser location is more than 50 km away
- 3 or more failed logins in the last 15 minutes: +25
- Unusual access time: +15 for local server time before 06:00 or from 22:00 onward
- 8 or more access requests in the last 2 minutes: +15
- Download/modify/delete action: +10
Score is capped at 100. Low: 0-29; Medium: 30-59; High: 60-100. ABAC denial stops before risk scoring.

LOCATION AND DEVICE NOTES
The device check uses a random browser cookie token, not hardware fingerprinting. A different browser/profile normally has a different token. Clear cookies or use another browser profile to demonstrate a new device. The first browser used by an account becomes its recognized browser.
Location is optional browser geolocation. On the dashboard, choose 'Save my usual location' and grant permission. When clicking a resource access link, the browser may ask for location permission; if shared, approximate coordinates are compared with the saved location. If permission is denied or unavailable, location is UNKNOWN and adds zero points. No background location tracking is performed. Browser geolocation works on localhost and HTTPS; it may not work on plain HTTP over a LAN address.
Unusual time means before 6:00 AM or 10:00 PM and later, using the computer/server local time. It is a demonstration rule, not a learned personal routine.

DEMONSTRATION
Use separate browser profiles (Chrome profile, Edge profile/InPrivate, Firefox) to keep Student, Faculty, Librarian and Admin signed in simultaneously. Do not use ordinary tabs in one profile because they share cookies/session. All profiles connect to the same Flask server and SQLite database.
Main Admin -> Risk Simulator: choose Student/Faculty/Librarian, resource, action and simulated signals to generate test logs. Simulation events are explicitly labelled in the audit log.

PERSISTENCE
SQLite database is stored in the Flask instance folder (instance/library.db). Access logs and account records persist across logout and app restarts. Do not delete this file if you want to keep history. A small schema migration adds new columns while preserving existing records. Back up the database before major changes. Uploaded files are stored in uploads/.

SECURITY / PROTOTYPE LIMITATIONS
This is an educational prototype, not production security software. Browser tokens can be copied/cleared and are not hardware identity. Geolocation is user-controlled and can be spoofed. IP/network reputation is not collected. Risk weights and thresholds are illustrative and require validation. OTP is fixed for demo only. Use HTTPS, CSRF protection, secure secrets, rate limiting and proper authentication before deployment.
