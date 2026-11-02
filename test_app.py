import time
import unittest

import app as lab


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.app = lab.create_app()
        self.c = self.app.test_client()
        self.c.post("/register", json={"username": "alice", "password": "Str0ngPassword1"})

    def login(self, u="alice", p="Str0ngPassword1"):
        return self.c.post("/login", json={"username": u, "password": p})

    # valid login
    def test_valid_login_and_profile(self):
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.c.get("/profile").get_json()["user"], "alice")

    def test_cookie_flags(self):
        cookie = self.login().headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    # validation
    def test_weak_password_rejected(self):
        r = self.c.post("/register", json={"username": "bob", "password": "weak"})
        self.assertEqual(r.status_code, 400)

    def test_bad_username_rejected(self):
        r = self.c.post("/register", json={"username": "a'; DROP--", "password": "Str0ngPassword1"})
        self.assertEqual(r.status_code, 400)

    # generic errors
    def test_generic_errors_identical(self):
        a = self.login(p="WrongPassword123")
        b = self.login(u="nobody", p="WrongPassword123")
        self.assertEqual(a.status_code, 401)
        self.assertEqual(a.get_json(), b.get_json())

    # brute force control
    def test_rate_limit_blocks_bruteforce(self):
        for _ in range(lab.MAX_ATTEMPTS):
            self.login(p="WrongPassword123")
        r = self.login()  # even the correct password is blocked now
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r.headers)

    # invalid sessions
    def test_no_session_rejected(self):
        self.assertEqual(self.c.get("/profile").status_code, 401)

    def test_logout_invalidates_session(self):
        self.login()
        self.c.post("/logout")
        self.assertEqual(self.c.get("/profile").status_code, 401)

    def test_idle_session_expires(self):
        self.login()
        with self.c.session_transaction() as s:
            s["last_seen"] = time.time() - lab.IDLE_TIMEOUT_SEC - 5
        self.assertEqual(self.c.get("/profile").status_code, 401)

    def test_tampered_cookie_rejected(self):
        self.login()
        self.c.set_cookie("sid", "tampered.value.here")
        self.assertEqual(self.c.get("/profile").status_code, 401)


if __name__ == "__main__":
    unittest.main()
