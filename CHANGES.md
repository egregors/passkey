Changes
=======

#### Unreleased (next major)

* Replace `User.PutCredential` and `UserStore.Update` with atomic `UserStore.UpdateCredential`.
  Storage reads and account creation must return detached snapshots; preserve registered
  credential data, concurrent updates, counters, and clone warnings.
* Require isolated session-store namespaces, unpredictable tokens, atomic consumption,
  expiration enforcement, and bounded storage. Full stores return `ErrSessionStoreFull` (HTTP 503).
* Validate authenticated-session purpose, identity, and expiration. Existing unmarked
  sessions and sessions using the old production cookie names require a new login.
* Use `__Host-` production cookies and reject duplicate session cookies.
  `WithInsecureCookie` uses ordinary names for local HTTP development.
* Require POST and a configured Origin for all ceremony endpoints and logout.
  Logout returns 204. Failed verification consumes the ceremony; restart at its begin endpoint.
* Return stable public errors with explicit HTTP statuses. `Auth` defaults to 401 on failure.
* Fix the example's shared user-store wiring, bound its session stores, and test its full
  registration/login/private-page/logout flow in CI.

#### ver.: 1.0.9 (05.08.2026)

* Go WebAuthn dependency update (v0.14.0 -> v0.17.4)
* JS SimpleWebAuthn dependency update (v13.2.0 -> v13.3.0)
* Synchronize the example module with the main Go dependencies
* Harden session cookies and unauthorized redirects

#### ver.: 1.0.8 (04.10.2025)

* Go WebAuthn deps update (v0.13.4 -> v0.14.0)
* JS SimpleWebAuthn deps update (v13.1.2 -> v13.2.0)

#### ver.: 1.0.7 (03.8.2025)

* Go deps update
* JS deps update

#### ver.: 1.0.6 (15.04.2025)

* Security update (go deps)

#### ver.: 1.0.5 (26.03.2025)

* Move to golangci-lint v2

#### ver.: 0.1.4 (22.03.2025)

* Dependency update

#### ver.: 0.1.3 (07.03.2025)

* Dependency update (js lib, go lib)
* Update linting rules
* Auth userID key for Auth middleware is now must by typed as auth.AuthUserIDKey

#### ver.: 0.1.2 (06.01.2025)

* Dependency update (js lib, _example app)

#### ver.: 0.1.1 (13.12.2024)

* Dependency update

#### ver.: 0.1.0 (28.11.2024)

* 🎉 First release!
