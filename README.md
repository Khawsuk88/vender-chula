# Vender Chula V3 — Pink Edition

A free student-to-student marketplace prototype for Chulalongkorn University. **V3 is suitable for local evaluation, not yet cleared for public deployment.**

## What's new since V2
- Forgot-password and single-use, 30-minute password reset links (email required)
- Database health endpoint at `/health`
- Pagination: 25 listings per page
- Input length and price bounds
- Configurable SQLite database path and startup checks for production secrets / HTTPS cookies
- Refined pink visual identity and clearer safe-trading footer
- V2 features retained: Chula email verification and resend, listings, moderation, favorites, sorting, sold status, photo processing, CSRF, basic rate limiting

## Windows VS Code quick start
1. Install Python 3.11+ and VS Code.
2. Extract ZIP; open folder `vender-chula-v3`.
3. Terminal:
   ```
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and replace `SECRET_KEY` with a random secret.
5. Configure real SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM. Without SMTP, users cannot complete email verification or reset passwords.
6. `python app.py`
7. Visit http://127.0.0.1:5000 and check http://127.0.0.1:5000/health
8. Set ADMIN_EMAIL to your own registered Chula email; restart and approve pending listings at `/admin`.

## Test checklist
- Homepage renders and `/health` returns `{"status":"ok"}`.
- Non-allowlisted email registration is rejected.
- Allowed Chula email gets a verification link and cannot sign in before clicking it.
- Verified user can sign in, post a photo listing, edit it, save it, mark it sold.
- Admin can approve/reject posts, reports are visible.
- Forgot password sends a link, link expires and cannot be reused.
- CSRF-less POST fails; invalid images fail.
- Test on iPhone/Android widths.

## Important caveats
- **Full runtime testing was not possible in the authoring environment** because Flask and Pillow could not be installed there. Python syntax and package structure were checked; real end-to-end testing remains mandatory.
- SMTP and actual Chula email-domain eligibility must be verified. Email ownership alone does not prove current student status.
- This is a local Flask/SQLite app with local uploads, not a scalable production architecture.
- Existing V2 SQLite data can be retained if its schema was created by V2. Back up data before upgrades. Legacy V1 databases may need migration.
- Basic in-memory rate limits do not work across multiple production workers. Add shared rate limiting, HTTPS, database/storage persistence, backups, monitoring, logging, abuse handling, admin audit trail, privacy policy and PDPA review before launch.
- The Flask development server is not for internet-facing deployment.
- Trademark clearance for Vender is outstanding.

## Safety
No escrow, payments, or guarantees. Encourage in-person inspection and public meetups. Never share credentials.

## V4: private messages (beta)

- Verified Chula users can open an approved listing and select **Chat with seller**.
- **Messages** in the navigation opens the inbox, showing unread counts.
- Each conversation belongs to a listing and has a buyer and seller.
- Text messages are limited to 2,000 characters; users can block one another.
- Chat refreshes on page reload (not WebSocket real-time); email/push notifications, message reports, and image attachments are not yet implemented.
- V4 automatically adds conversation tables to an existing V3 SQLite database on first run. **Back up `vender.db` before upgrading.**
- Existing V3 deployment and email verification limitations still apply. This is a local beta build, not a production-hardened service. Run security and functional tests before allowing real users.
