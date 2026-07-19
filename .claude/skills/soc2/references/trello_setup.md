# Trello Setup

The Trello scanner no-ops with a clear message until `secrets/trello-credentials.json` exists — this is expected, not an error, so `--scope all` runs cleanly before Trello is configured.

## Generating a read-only token on a dedicated account

Trello API tokens are account-scoped, not per-resource: a token can only see what the *authorizing account* can see, and `scope=read` makes it read-only (no writes) but does not restrict *which* boards it can read. To keep blast radius small:

1. Create a **dedicated Trello account** (e.g. `soc2-scanner@yourdomain.com`) rather than using a personal admin account.
2. Have a Workspace admin add that account to the Workspace with the lowest role available — plain "Member" on Free/Standard plans, or the **Observer** board role if on Business Class/Premium/Enterprise (Observer is genuinely read-only per board).
3. While logged in as that account, get an API key at `https://trello.com/power-ups/admin/api-key` (or `https://trello.com/app-key`).
4. Generate a read-only token by visiting:
   ```
   https://trello.com/1/authorize?expiration=never&scope=read&response_type=token&key=YOUR_KEY&name=soc2-skill
   ```
   Approve access, then copy the resulting token.
5. Save both values to `secrets/trello-credentials.json`:
   ```json
   {"api_key": "YOUR_KEY", "token": "YOUR_TOKEN"}
   ```

## Visibility caveat

To see "users and their access to boards," the scanning account needs to be a Workspace member — `GET /1/organizations/{id}/boards` and `GET /1/boards/{id}/memberships` only return what that account can see. It does not need to be a Workspace admin, but it will see less on private boards it hasn't been explicitly added to. If a board's membership list is expected but missing from scan results, confirm the dedicated account has been added to that board.

## Config

`trello.organizations` in `config/soc2.config.yaml` can list specific organization IDs to scan; leave it empty to auto-discover every organization the token's account belongs to.

## Report chapters

Same dedicated-chapter treatment GCP/Bitbucket/AWS get (not a flat list of resource IDs):

- **Organization Members** — workspace-level membership (`GET /1/organizations/{id}/memberships`), distinct from per-board membership. Flags `admin` member type and `deactivated` (removed from the workspace but the membership record lingers, `medium`) or `unconfirmed` (never verified their account, `low`) accounts. Note: `email` is not exposed for other members via this endpoint even with org-admin visibility on this token - confirmed live, not a scope gap this scanner can work around.
- **Boards** — name, visibility, last activity date (`dateLastActivity`, not diffed - it changes on every real edit and would otherwise flood the diff table with noise every run).
- **Board Members** — one row per member with every board they can access and their permission level on each (`normal`/`observer`/`admin`), grouped the same way Bitbucket's "Repo Permissions" chapter groups by principal. Grouped by Trello's internal member ID, not display name - this workspace has multiple distinct accounts sharing the same full_name (e.g. several "Jane Doe" accounts with different usernames), so grouping by name alone would silently merge unrelated accounts' access into one row. Each member's own username is shown in parentheses to disambiguate. Also shows each member's account-wide `dateLastActive` (red if >3 months stale) - this field isn't returned by the batched board/org membership endpoints even when requested, so it costs one extra `GET /1/members/{id}` call per *unique* member per scan (cached, so a member on N boards is only fetched once). Closed/archived boards are grayed out inline within a member's board list.

It's normal and expected for **Board Members** to list far more people than **Organization Members** - Trello board access and workspace membership are two separate systems. A board with `"selfJoin": true` in its prefs lets anyone with the invite link join that specific board directly without ever being added to the workspace roster. Worth periodically reconciling: someone who shows up across many boards but never in Organization Members has accumulated access purely through board-level invites/self-join, not a deliberate workspace-level grant.
