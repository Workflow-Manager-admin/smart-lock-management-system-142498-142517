from rest_framework.test import APITestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status

User = get_user_model()

class HealthTests(APITestCase):
    def test_health(self):
        url = reverse('Health')  # Make sure the URL is named
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"message": "Server is up!"})

class AuthTests(APITestCase):
    def test_register_login_and_me(self):
        reg_url = reverse('register')
        login_url = reverse('login')
        user_data = {"username": "testuser", "password": "pw123456", "email": "test@x.com"}
        # Register
        response = self.client.post(reg_url, user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Login
        response = self.client.post(login_url, {"username": "testuser", "password": "pw123456"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        token = response.data["access"]
        # Test 'me'
        me_url = reverse('me')
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        response = self.client.get(me_url)
        self.assertEqual(response.data["username"], "testuser")

class LockTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="aaa", password="pw123456", email="aaa@x.com")
        self.client.login(username="aaa", password="pw123456")
        self.client.force_authenticate(user=self.user)
    def test_create_and_lock_unlock(self):
        # Create lock
        url = reverse('locks-list')
        data = {"name": "Front Door", "location": "Main Entrance", "description": ""}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        lock_id = response.data["id"]
        # Lock
        lock_url = reverse('locks-lock', kwargs={"pk": lock_id})
        resp = self.client.post(lock_url)
        self.assertEqual(resp.data["status"], "locked")
        # Unlock
        unlock_url = reverse('locks-unlock', kwargs={"pk": lock_id})
        resp = self.client.post(unlock_url)
        self.assertEqual(resp.data["status"], "unlocked")
