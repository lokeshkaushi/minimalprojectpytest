from django.test import Client
from django.contrib.auth import authenticate
from unittest.mock import MagicMock
from accounts.models import *
import unittest.mock
import pytest
from django.urls import reverse
from django.utils import timezone
from unittest.mock import patch, Mock
from rest_framework import status
#from django.test import APITestCase
import string
import random
from rest_framework import status
import requests
from django.http import HttpResponse
from rest_framework.test import APIClient
import jwt
from unittest import mock
from rest_framework.authtoken.models import Token 
import json



'''@pytest.mark.django_db
def test_registration(client, user_data):
    mock_response = requests.models.Response()
    mock_response.status_code = 201
    mock_response._content = b'{"message": "registration successful"}'

    with unittest.mock.patch("requests.post", return_value=mock_response):
        response = client.post(reverse('Register'), user_data, format="json")
        if response.status_code != 201:
           print({"message": "registration Unsuccessful"})
        assert response.status_code == 201
        

@pytest.mark.django_db    
def test_login(client, user_data):
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate(
            
            test_registration(client, user_data)
            )
        
        response = client.post(reverse('login'),
                               {
            'email': user_data['email'],
            'password': user_data['password'],
        })
        if response.status_code != 200:
            print({"message": "Unauthorized User"})
        assert response.status_code == 200

@pytest.mark.django_db
def test_forgot_password(client,user_data):
    # First, you need to create a user
    user = CustomUser.objects.create_user(**user_data)
    print(user)
        
    # Then, you can simulate a forgot password request by sending a POST request to the API
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate
           
    response = client.post(reverse('forget_password'), {'email': user_data['email']}, content_type='application/json')
    assert response.status_code == 202
    assert response.data['message'] == 'Reset Password Email has been sent to your Email ID'


    # You can use MagicMock to mock the send_mail function and check if it's called
    send_password_reset_email = MagicMock(return_value=True)
    send_password_reset_email(to=[user_data['email']], subject='Password reset request', message='Reset your password',email_from = settings.EMAIL_HOST_USER)
    send_password_reset_email.assert_called_once()

    # Finally, you can check if the forget_password_token field is updated
    user = CustomUser.objects.get(email=user_data['email'])
    assert user.forget_password_token is not None
    if response.status_code != 202:
            print({"message": "Unauthorized User"})
    assert response.status_code == 202


@pytest.mark.django_db
def test_change_password(client, change_password_data,user_data):
    # First, you need to create a user and set the forget_password_token field
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate(
            
            test_forgot_password(client, user_data)
            )
    user = CustomUser.objects.create_user(username = 'testuser')
    user.forget_password_token = 'token'
    user.save()
    
    # Then, you can simulate a change password request by sending a POST request to the API with the token
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate

    response = client.post(reverse('change_password', kwargs={'token': 'token'}), change_password_data, content_type='application/json')
    if response.status_code != 205:
            print({'message': "Invalid credentials, try again"})
    assert response.status_code == 205
    assert response.data['message'] == 'Password change successfully now login'
    
    # Finally, you can check if the password has been updated for the user
    user = CustomUser.objects.get(username='testuser')
    assert user.check_password(change_password_data['new_password']) is True

@pytest.mark.django_db
def test_create_blog(client,user_data,blog_data):
    user = test_login(client,user_data)
    print (user)
    #If the user exists and is authenticated, the function returns True
    user is not None and user.is_authenticated
    #return user is not None and user.is_authenticated
    user is not None and user
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"key": "value"}
    
    #Make the POST request to create the blog post
    with unittest.mock.patch("requests.post", return_value=mock_response):    
        response = client.post(reverse('blog'), blog_data, format="json")
        return response
        if response.status_code != 201:
           print({"message":"blog post not created"})
        assert response.status_code == 201'''



'''@pytest.mark.django_db
def test_create_post(create_user):
    url = reverse('user_post')
    data = {'title': 'Test post', 'body': 'This is a test post.'}
    client = client()
    #client = APITestCase().client
    client.login(username=create_user.username, password=create_user.password)
    
    with patch('posts.views.create_post') as mock_create_post:
        mock_create_post.return_value = Mock(status_code=status.HTTP_201_CREATED)
        response = client.post(url, data, format='json')
        assert response.status_code == status.HTTP_201_CREATED'''


'''@pytest.mark.django_db
def test_update_blog(client,user_data,blog_data):
    
    user = test_login(client,user_data)
    print (user)
    #If the user exists and is authenticated, the function returns True
    user is not None and user.is_authenticated
    #return user is not None and user.is_authenticated
    user is not None and user
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"key": "value"}
    
    #Make the POST request to create the blog post update
    with unittest.mock.patch("requests.post", return_value=mock_response):
        
        response = client.post(('blog_update'), blog_data,format="json")
        return response
        if response.status_code != 201:
           print({"message":"blog post not created"})
        assert response.status_code == 201'''

'''@pytest.mark.django_db
def test_update_blog(client, user_data, blog_data, blog_post_data):
    # Login the active user
    user = test_login(client, user_data)
    user is not None and user.is_authenticated
    
    #If the user exists and is authenticated, the function returns True
   
    # Create a mock response object with a 401 status code
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"error": "Unauthorized"}
    
    # Patch the requests.post method to return the mock response object
    with unittest.mock.patch("requests.post", return_value=mock_response):
        # Make the POST request to create the blog post update
        response = client.post('/blog_update/<PK:id>/', blog_data, format="json")
        
        # Check that the response status code is 401
        assert response.status_code == 401
        
        # Check that the error message is returned in the response JSON
        assert "error" in response.json()'''
        






'''@pytest.mark.django_db
def test_user_social_view(client,user_Social_data):
    
    # Get JWT token for the user
    client = APIClient()
    response = client.post(reverse('user_social'), user_Social_data,content_type="application/json")
   # token = response.data['token']

    # Add JWT token to the client 
    client.credentials(HTTP_AUTHORIZATION='Bearer ')
    payload = {'username': 'testuser'}
    token = jwt.encode(payload, 'secret', algorithm='HS256')

    # Set the JWT token in the Authorization header
    client.credentials(HTTP_AUTHORIZATION='Bearer ' + token.decode('utf-8'))

    # Create mock data to be posted
    mock_data = user_Social_data
    #mock_data = user_Social_data{'username': 'test_user', 'provider': 'provider_name', 'uid': 'uid_value'}

    # Patch the serializer to return the mock data
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate
        instance = mock_authenticate.return_value
       # instance.is_valid.return_value = True
        instance.return_value = mock_data

        # Make a post request to the view
        response = client.post('/user_social/', data=mock_data,content_type="application/json")

        # Assert the request was successful
        if response.status_code != 200:
            print({"message":"user social not  create "})
        print(response)
        assert response.status_code == 200'''

       


'''@pytest.mark.django_db
def test_user_social_view(client,user_Social_data,user_data):
    # Get JWT token for the user
    client = APIClient()
    response = client.post(reverse('user_social'), user_Social_data,content_type="application/json")
    #token = response.data['token']

    # Add JWT token to the client 
    client.credentials(HTTP_AUTHORIZATION='Bearer ')
    payload = {'username': 'testuser'}
    token = response.data['token']


    # Set the JWT token in the Authorization header
    client.credentials(HTTP_AUTHORIZATION='Bearer ' + token.decode('utf-8'))

    # Create mock data to be posted
    mock_data = user_Social_data

    # Create a mock User object
    user = unittest.mock.Mock(spec=CustomUser)
    user.is_authenticated = True

    # set up the serializer to return valid data
    user.return_value.is_valid.return_value = True
    user.return_value.save.return_value = {'id': 1, **user_data}

    # send the request to the view
    response = client.post('/user_social/', data=user_data)

    # assert that the response has a success status code and returns the expected data
    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'id': 1, **user_data}

    # Patch the authenticate function to return the mock User object
    # with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
    #     mock_authenticate.return_value = user

    #     # Make a post request to the view
    #     response = client.post('/user_social/',data=mock_data,content_type="application/json")
        
    #     # Assert the request returns a 401 status code
    #     if  response.status_code != 200:
    #         print({"message":"user social not  create "})

    #     # Assert the request was successful
    #     assert response.status_code == 200  ''' 

'''@pytest.mark.django_db
def test_user_social_view(client,user_Social_data,user_data):
    # First, you need to create a user and set the forget_password_token field
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate(
            
            test_login(client, user_data)
            )
    user = CustomUser.objects.create_user(username = 'testuser')
    user.user_social_token = 'token'
    user.save()
    
    # Then, you can simulate a change password request by sending a POST request to the API with the token
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate

    
    response = client.post(reverse('user_social', kwargs={'token': 'token_value'}), user_Social_data, format='json')

    if response.status_code != 200:
            print({'message': "Invalid credentials, try again"})
    assert response.status_code == 200
    assert response.data['message'] == 'Password change successfully now login'
    
    # Finally, you can check if the password has been updated for the user
    user = CustomUser.objects.get(username='testuser')
   # assert user.check_password(user_Social_data['new_password']) is True
    assert response.status_code == status.HTTP_401_UNAUTHORIZED'''







'''@patch('accounts.views.jwt_encode_handler')
def test_register_api_validation_error(mock_jwt_encode, client, user_data, mock_jwt_token):
    # Mock jwt_encode_handler to return mock jwt token
    mock_jwt_encode.return_value = mock_jwt_token

    # Remove the username field from the user data to cause a validation error
    del user_data['username']

    # Make a POST request to the register endpoint with invalid data
    response = client.post('/register/', data=user_data)

    # Check that the response status code is 400
    assert response.status_code == 400

    # Check that the response data contains the error message
    assert 'username' in response.data
    assert response.data['username'][0] == 'This field is required.'

    # Check that a user with the specified email does not exist in the database
    assert not CustomUser.objects.filter(email=user_data['email']).exists()'''


'''@pytest.mark.django_db
def test_login(client, user_data):
    test_registration(client, user_data)
    with mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        user = authenticate(username=user_data['email'], password=user_data['password'])
        mock_authenticate.return_value = user
        
        response = client.post(reverse('login'), data=user_data)

        if response.status_code == 200:
            token = Token.objects.create(user=user)
            var = response.json()['access']
            return var
            print(response.json()['access'])
            # assert response.data['token'] == token.key
            
        else:
            assert response.status_code == 401'''

# @pytest.mark.django_db
# def test_create_post(create_user):
#     test_login(client,create_user)
#     url = reverse('user_post')
#     data = {'title': 'Test post', 'body': 'This is a test post.'}
#     client = client()
#     client.force_authenticate(user=create_user)
#     #client = APITestCase().client
#    # client.login(username=create_user.username, password=create_user.password)
#     client.credentials(HTTP_AUTHORIZATION=f'Token {create_user.auth_token.key}')


#     with patch('posts.views.create_post') as mock_create_post:
#         mock_create_post.return_value = Mock(status_code=status.HTTP_201_CREATED)
#         response = client.post(url, data, format='json')
#         assert response.status_code == status.HTTP_201_CREATED

'''@pytest.mark.django_db
def test_registration(client, user_data):
    mock_response  = MagicMock()
    mock_response.status_code = 201
    mock_response._content = b'{"message": "registration successful"}'

    with unittest.mock.patch("requests.post", return_value=mock_response):
        response = client.post(reverse('Register'), user_data, format="json")
        return response.json()
        
        

@pytest.mark.django_db
def test_login(client,blog_data, user_data):
    test_registration(client, user_data)
    with mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        user = authenticate(username=user_data['email'], password=user_data['password'])
        mock_authenticate.return_value = user
        
        response = client.post(reverse('login'), data=user_data)

        if response.status_code == 200:
            if Token.objects.filter(user=user).exists():
                old_token = Token.objects.get(user=user)
                old_token.delete()
            token = Token.objects.create(user=user)
            print(token)
            return token.key
           
            #var = response.json()['access']
            #return var
            print(response.json()['access'])
            test_create_blog(client,blog_data,user_data,token)
            assert response.data['token'] == token.key
            
        else:
            assert response.status_code == 401


@pytest.mark.django_db
def test_User_Post(client, user_data, post_data):
    token=test_login(client,post_data, user_data)

    # Create a mock response object with a 401 status code
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"error": "Unauthorized"}
    
  # Make the POST request to create the user  post
    with unittest.mock.patch("requests.post", return_value= mock_response):
        mock_response = client.post(reverse('user_post'), post_data,token)
        if mock_response.status_code == 201:
            print({"message":"user post created"})

        # Check that a token was created for the user
            token = Token.objects.filter(user=post_data['id']).first()
            print(token)
            if token is not None:
                assert mock_response.status_code == 201

@pytest.mark.django_db
def test_post_view_user(client, user_data, post_data):
    token=test_login(client,post_data, user_data)
  # Make the POST request to create the  post
    response = client.get(reverse('Post_view_user'), post_data,token)
    if response.status_code == 201:
        print({"message":"user post get data"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=post_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201

@pytest.mark.django_db
def test_view_post(client, user_data, post_data):
    token=test_login(client,post_data, user_data)
  # Make the GET request to create the post
    response = client.get(reverse('view_post'), post_data,token)
    if response.status_code == 201:
        print({"message":"user post latest post get"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=post_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201

@pytest.mark.django_db
def test_Post_update(client, user_data, post_data):
    token=test_login(client,post_data, user_data)
  # Make the UPDATE request to user post update
    response = client.put(reverse('blog_update',args=[post_data['post_id']]), post_data,token)
    if response.status_code == 201:
        print({"message":"user Post update"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=post_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201








@pytest.mark.django_db
def test_create_blog(client, user_data, blog_data):
    token=test_login(client,blog_data, user_data)
  # Make the POST request to create the blog post
    response = client.post(reverse('blog'), blog_data,token)
    if response.status_code == 201:
        print({"message":"blog post created"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=blog_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 200


@pytest.mark.django_db
def test_update_blog(client, user_data, blog_data):
    token=test_login(client,blog_data, user_data)
  # Make the PUT request to update the blog post
    response = client.put(reverse('blog_update',args=[blog_data['id']]), blog_data,token)
    if response.status_code == 201:
        print({"message":"blog post update blog"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=blog_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201


@pytest.mark.django_db
def test_blog_view(client, user_data, blog_data):
    token=test_login(client,blog_data, user_data)
  # Make the POST request to create the blog post
    response = client.post(reverse('blog'), blog_data,token)
    
    if response.status_code == 201:
        print({"message":"blog post get"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=blog_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201

@pytest.mark.django_db
def test_blog_delete(client, user_data, blog_data):
    token=test_login(client,blog_data, user_data)
  # Make the DELETE request to create the blog post
    response = client.post(reverse('blog_delete',args=[blog_data['id']]), blog_data,token)
    if response.status_code == 201:
        print({"message":"blog post delete blog"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=blog_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201
@pytest.mark.django_db
def test_delete_blog(client, blog_data, user_data):
    token = test_login(client, blog_data, user_data)
    url = reverse('blog_delete', args=[blog_data['id']],format='application/json')
    response = client.post(url, data=blog_data, HTTP_AUTHORIZATION=f'Bearer {token}')
    
    assert response.status_code == 201 # Expected response status code
    assert not Blog.objects.filter(id=blog_data['id']).exists() # Check if the blog has been deleted


@pytest.mark.django_db
def test_User_Social(client, user_data, user_Social_data):
    token=test_login(client,user_Social_data, user_data)
  # Make the POST request to create the user_social
    response = client.post(reverse('user_social'), user_Social_data,token)
    if response.status_code == 201:
        print({"message":"user social post created"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=user_Social_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201


@pytest.mark.django_db
def test_User_Social_view(client, user_data, user_Social_data):
    token=test_login(client,user_Social_data, user_data)
  # Make the Get request to user social data
    response = client.get(reverse('user_social'), user_Social_data,token)
    if response.status_code == 201:
        print({"message":"user Social data get "})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=user_Social_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201

@pytest.mark.django_db
def test_User_Social_Update(client, user_data,user_Social_data):
    token=test_login(client,user_Social_data, user_data)
  # Make the UPDATE request to update the User Social Update
    response = client.put(reverse('blog_update',args=[user_Social_data['id']]), user_Social_data,token)
    if response.status_code == 201:
        print({"message":"User Social Update data"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=user_Social_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201'''


            
'''@pytest.mark.django_db
def test_user_social_view(client,user_Social_data,token):
    
    # Get JWT token for the user
    client = APIClient()
    response = client.post(reverse('user_social'), user_Social_data,content_type="application/json")
    token = response.data['token']

    # Add JWT token to the client 
    client.credentials(HTTP_AUTHORIZATION='Bearer ')
    payload = {'username': 'testuser'}
    token = jwt.encode(payload, 'secret', algorithm='HS256')

    # Set the JWT token in the Authorization header
    client.credentials(HTTP_AUTHORIZATION='Bearer ' + token.decode('utf-8'))

    # Create mock data to be posted
    mock_data = user_Social_data
    #mock_data = user_Social_data{'username': 'test_user', 'provider': 'provider_name', 'uid': 'uid_value'}

    # Patch the serializer to return the mock data
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate
        instance = mock_authenticate.return_value
       # instance.is_valid.return_value = True
        instance.return_value = mock_data

        # Make a post request to the view
        response = client.post('/user_social/', data=mock_data,content_type="application/json")

        # Assert the request was successful
        if response.status_code != 200:
            print({"message":"user social not  create "})
        print(response)
        assert response.status_code == 200'''


'''@pytest.mark.django_db
def test_delete_blog(client, blog_data, auth_token, mocked_delete_blog):
    url = reverse('blog_delete', kwargs={'pk': mocked_delete_blog.pk})
    client = Client()
    client.update({'Authorization': auth_token})
    response = client.get(url)

    assert response.status_code == status.HTTP_205_RESET_CONTENT
    assert response.data == {'message': 'Your blog delete successfully'}'''


'''@pytest.mark.django_db
def test_create_blog(api_client ,user_data, blog_data):
    token=test_login(api_client ,blog_data, user_data)
    #token = None
    if not token:
        print("Error: test_login returned None")
        return
    
    auth_header = {
      "authorization" : f'Bearer {token}'
    }
     
    print(f"Auth header: {token}")
    
    # serialized_data = json.dumps(blog_data).encode('utf-8')
    # print(f"Serialized data: {serialized_data}")
    api_client.force_authenticate(user= token)
    
    response = api_client.post(reverse('blog'),json = blog_data, content_type = "application/json",**auth_header)
    
    #print(f"Response: {response}")
    # response_json = response.content.decode('utf-8')
    if response.status_code == 201:
        response_dict = json.loads(response)
        
        print({"message": "Blog post created"})
    else:
     
     print({"message":"Blog post not created"})'''




'''@pytest.mark.django_db
def test_User_Social_view(client, user_data, user_Social_data):
    token=test_login(client,user_Social_data, user_data)
  # Make the Get request to user social data
    response = client.get(reverse('user_social'), user_Social_data,token)
    if response.status_code == 201:
        print({"message":"user Social data get "})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=user_Social_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201

@pytest.mark.django_db
def test_User_Social_Update(client, user_data,user_Social_data):
    token=test_login(client,user_Social_data, user_data)
  # Make the UPDATE request to update the User Social Update
    response = client.put(reverse('blog_update',args=[user_Social_data['id']]), user_Social_data,token)
    if response.status_code == 201:
        print({"message":"User Social Update data"})
    
    # Check that a token was created for the user
        token = Token.objects.filter(user=user_Social_data['id']).first()
        print(token)
        if token is not None:
         assert response.status_code == 201'''