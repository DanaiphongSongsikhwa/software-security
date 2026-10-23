"""Regression checks for week10 defenses; no external targets."""
import unittest
from unittest.mock import patch
import defended_api as api


class DefenseTests(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        api.SESSIONS.clear()
        api._attempts.clear()
        api.USERS = {k: v for k, v in api.USERS.items() if k <= 3}
        api._next_id = 4

    def token(self, username="alice", password="alice123"):
        response = self.client.post('/api/login', json={
            'username': username, 'password': password})
        self.assertEqual(response.status_code, 200)
        return {'Authorization': 'Bearer ' + response.json['access_token']}

    def test_ownership_and_admin(self):
        headers = self.token()
        self.assertEqual(self.client.get('/api/users/1/orders', headers=headers).status_code, 200)
        self.assertEqual(self.client.get('/api/users/3/orders', headers=headers).status_code, 403)
        admin = self.token('carol', 'carol123')
        self.assertEqual(self.client.get('/api/users/2/orders', headers=admin).status_code, 200)

    def test_header_forgery_and_fake_token(self):
        for headers in ({}, {'X-User-Id': '3'}, {'Authorization': 'Bearer fake'}):
            self.assertEqual(self.client.get('/api/users/3/orders', headers=headers).status_code, 401)

    def test_expired_token(self):
        headers = self.token()
        token = headers['Authorization'].split()[1]
        uid, expires = api.SESSIONS[token]
        with patch.object(api.time, 'monotonic', return_value=expires):
            self.assertEqual(self.client.get('/api/users/1/orders', headers=headers).status_code, 401)
        self.assertNotIn(token, api.SESSIONS)

    def test_mass_assignment_and_password_storage(self):
        response = self.client.post('/api/users', json={'username': 'mallory', 'password': 'x',
            'id': 3, 'is_admin': True, 'balance': 1000000, 'password_hash': 'attacker'})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json, {'id': 4, 'username': 'mallory', 'is_admin': False, 'balance': 0})
        self.assertNotIn('password', api.USERS[4])
        self.assertTrue(api.check_password_hash(api.USERS[4]['password_hash'], 'x'))
        self.assertEqual(self.client.post('/api/users', json={'username': 'mallory', 'password': 'x'}).status_code, 409)

    def test_bad_json_and_fields(self):
        for body in ([], 'x', None, {}, {'username': [], 'password': 'x'},
                     {'username': 'alice', 'password': ''}, {'username': 'x'*65, 'password': 'x'}):
            self.assertEqual(self.client.post('/api/users', json=body).status_code, 400)
        self.assertEqual(self.client.post('/api/users', data='{', content_type='application/json').status_code, 400)
        self.assertEqual(self.client.post('/api/users', data='x'*5000, content_type='application/json').status_code, 413)

    def test_throttle_and_window(self):
        with patch.object(api.time, 'monotonic', return_value=100):
            statuses = [self.client.post('/api/login', json={'username': 'alice', 'password': 'wrong'}).status_code for _ in range(7)]
        self.assertEqual(statuses, [401]*5 + [429]*2)
        with patch.object(api.time, 'monotonic', return_value=160):
            self.assertEqual(self.client.post('/api/login', json={'username': 'alice', 'password': 'wrong'}).status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
