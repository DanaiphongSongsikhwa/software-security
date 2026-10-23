# Week 10 quiz revision - not a submitted attempt

1. **a) Broken Object Level Authorization.** The API must check whether the caller can access the requested object.
2. **b) Client input is bound to model fields it should not set.** For example, a normal user controls `is_admin`.
3. **b) Brute force / resource exhaustion.** Rate limits reduce the number of guesses and the work done by the server.
4. **b) It gets logged in servers, proxies, and browser history.** Send credentials through an appropriate authorization header over HTTPS instead.
5. **b) Function.** BFLA means Broken Function Level Authorization, such as letting a normal user call an admin action.
6. The endpoint was `POST /api/users`. It accepted `is_admin: true` and `balance: 1000000` from the JSON body. The fix is to allow only `username` and `password`, and let the server set the ID, role, and balance. A personal flag has not been obtained; the local response contains only `FLAG{massassign_demo}`, which must not be presented as a personal flag.

AI disclosure: these revision answers were drafted by Codex. The student must follow
the course rules when taking the individual quiz. No quiz platform was accessed.
