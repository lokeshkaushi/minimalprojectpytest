# from django.test import TestCase
# from accounts.models import *
# from rest_framework.test import APIClient
# from rest_framework import status
# import factory
# from django.http import HttpResponse
# import uuid
# import random
# from django.test import TestCase
# from unittest.mock import MagicMock


# class RegisterApiTestCase(TestCase):
#     def setUp(self):
#         self.request = MagicMock()
#         self.User = CustomUser

#     def test_register_api(self):
#         # Generate dynamic values for the test data
        
#         username = 'testuser' + str(uuid.uuid4())[:8]
#         email = 'testemail' + str(uuid.uuid4())[:8] + '@example.com'
#         password = 'testpassword' + str(uuid.uuid4())[:8]
#         first_name = 'testfirst_name'  + str(uuid.uuid4())[:8]
#         last_name = 'testlast_name'  + str(uuid.uuid4())[:8]
#         # Generate a valid mobile number for all countries
#         print(username)
#         number = '+' + str(random.randint(1, 999)) + str(random.randint(100000000, 999999999))
       
#         data = {
#             'username': username,
#             'email': email,
#             'first_name' : first_name,
#             'last_name' : last_name,
#             'password': password,
#             'number': number,
#         }
#         self.request.data = data

#         # Call the registration API
#         response = self.client.post('http://127.0.0.1:8000/register/', data,format="json")
#         print(response.json())
#         # Assert that the API returns a 201 status code
#         self.assertEqual(response.status_code, 201)
        
#         #Assert that a user was created with the correct information

#         self.assertTrue(CustomUser.objects.filter(username=username).exists())
#         self.assertTrue(CustomUser.objects.filter(email=email).exists())
#         self.assertTrue(CustomUser.objects.filter(first_name=first_name).exists())
#         self.assertTrue(CustomUser.objects.filter(last_name=last_name).exists())
#         self.assertTrue(CustomUser.objects.filter(number=number).exists())
#         self.assertFalse(CustomUser.objects.filter(password=password).exists())


'''@pytest.mark.django_db
def test_registration(client, user_data):
    response = client.post(reverse('Register'), user_data, format="json")
    _data = response.json()
    assert response.status_code == 201
    assert _data.get('status') == True
    assert _data.get('message') == "Register successfully"
    #print("Registration successful")'''




'''class LoginApiTestCase(TestCase):
    def setUp(self):
        self.request = MagicMock()
        self.User = CustomUser

    def test_login_api(self):
        # Generate dynamic values for the test data
        
        email = 'testemail' + str(uuid.uuid4())[:8] + '@example.com'
        password = 'testpassword' + str(uuid.uuid4())[:8]
        
        # Generate a valid mobile number for all countries
        data = {
            
            'email': email,
            'password': password,
        }
        self.request.data = data

        # Call the registration API
        response = self.client.post('http://127.0.0.1:8000/login/', data,format="json")
        #print(response.json())
        # Assert that the API returns a 201 status code
        self.assertEqual(response.status_code, 201)
        
        #Assert that a user was created with the correct information
        
        self.assertTrue(CustomUser.objects.filter(email=email).exists())
        # self.assertTrue(CustomUser.objects.filter(first_name=first_name).exists())
        # self.assertTrue(CustomUser.objects.filter(last_name=last_name).exists())
        # self.assertTrue(CustomUser.objects.filter(number=number).exists())
        self.assertTrue(CustomUser.objects.filter(password=password).exists())'''


'''@pytest.mark.django_db
def test_forgot_password(client, user_data):
    # Get the URL for the forget password view
    
    with unittest.mock.patch('django.contrib.auth.authenticate') as mock_authenticate:
        mock_authenticate.return_value = authenticate(
        test_login(client, user_data))
           
    # Call the API to request a password reset
    response = client.post(reverse('forget_password'),{'email': user_data['email']}, content_type='application/json')
    

    # Check that a password reset email has been sent
    send_password_reset_email = MagicMock()
    send_password_reset_email()
    send_password_reset_email.assert_called_once()
    
    # Check that the password reset token has been added to the user's profile
    
    user = CustomUser.objects.get(email= user_data['email'])
    assert user.forget_password_token is not None
    assert user.email is not None
    #assert response.status_code == 202
    if response.status_code != 202:
            print({"message": "Unauthorized User"})
    assert response.status_code == 202'''

   



from unittest.mock import patch

'''@patch('boto3.resource')
@pytest.mark.django_db()
def test_create_blog_post(mocked_resource,client,user_data,blog_data):
    # Create a mock DynamoDB table
    mocked_table = MagicMock()
    mocked_resource.return_value.Table.return_value = mocked_table

    # Set up the mock table to contain a user
    user = CustomUser.objects.create_user(**user_data)
    user.save()
    token = test_login(mocked_resource, client, user_data)
    print(token)
    # mocked_table.query.return_value = {'Items': [{'username': {'S': 'test_user'}, 'password': {'S': 'password123'}}]}
    mocked_table.query.return_value = {'Items': [{'blog_name': blog_data['blog_name'], 'tag_name': blog_data['tag_name']}]}
    # Send a request to the login endpoint
    response = client.post(reverse('blog_post'), user_data, Authorization=f'Bearer {token}', format='json')
    print(response.content)
    # Check that the response is correct
    assert response.status_code == 200
    print(response.json()['access'])
    return (response.json()['access'])
    # assert json.loads(response.content) == {'message': 'login successfully'}'''


'''@pytest.mark.django_db
def test_create_blog_post(user_data):
    # Create a mock serializer
    serializer = MagicMock(spec=BlogSerializer)
    serializer.is_valid.return_value = True
    serializer.save.return_value = Blog(blog_name='Test Blog', tag_name='This is a test blog post')

    # Create a mock DynamoDB table
    mocked_table = MagicMock()
    mocked_table.put_item.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

    # Mock the boto3.resource function
    mocked_resource = MagicMock()
    mocked_resource.Table.return_value = mocked_table

    # Set up the test client
    client = APIClient()

    # Set up the test user
    user = CustomUser.objects.create_user(**user_data)
    user.save()
    token = test_login(mocked_resource, client, user_data)

    # Set up the blog data
    blog_data = {'blog_name': 'Test Blog', 'tag_name': 'This is a test blog post.'}

    # Make the POST request to create the blog post
    with patch('boto3.resource', return_value=mocked_resource), patch('accounts.serializers.BlogSerializer', return_value=serializer):
        response = client.post(reverse('blog'), blog_data, json.dumps(blog_data))

    # Check that the response is correct
    assert response.status_code == 201
    assert Blog.objects.filter(blog_name='Test Blog', tag_name='This is a test blog post.').exists()

    # Clean up
    Blog.objects.filter(blog_name='Test Blog', tag_name='This is a test blog post.').delete()
    user.delete()'''





'''@pytest.mark.django_db
def test_create_blog_post(user_data):
    # Create a mock serializer
    serializer = MagicMock(spec=BlogSerializer)
    serializer.is_valid.return_value = True
    serializer.save.return_value = Blog( blog_name='Test Blog', tag_name='This is a test blog post')

    # Create a mock DynamoDB table
    mocked_table = MagicMock()
    mocked_table.put_item.return_value = {'ResponseMetadata': {'HTTPStatusCode': 201}}

    # Mock the boto3.resource function
    mocked_resource = MagicMock()
    mocked_resource.Table.return_value = mocked_table

    # Set up the test client
    client = APIClient()

    # Set up the test user
    user = CustomUser.objects.create_user(**user_data)
    user.save()
    token = test_login(mocked_resource, client, user_data)

    # Set up the blog data
    blog_data = {'blog_name': 'Test Blog', 'tag_name': 'This is a test blog post.'}

    # Make the POST request to create the blog post
    with patch('boto3.resource', return_value=mocked_resource), patch('accounts.serializers.BlogSerializer', return_value=serializer):
        #response = client.post(reverse('blog_post'), blog_data, HTTP_AUTHORIZATION=f'Token {token}', format='json')
        response = client.post(reverse('blog'), blog_data, content_type="application/json")
    # Check that the response is correct
    #assert response.status_code == 201
    assert Blog.objects.filter(blog_name='Test Blog', tag_name='This is a test blog post.').exists()

   # Clean up
   # Blog.objects.filter(blog_name='Test Blog', tag_name='This is a test blog post.').delete()
   # user.delete()'''

# '''@patch('boto3.resource')
# @pytest.mark.django_db
# def test_Profile_Pic(client,test_create_Profile_Pic,create_user_data):
#     #First, you need to create a user 
#     user = CustomUser.objects.create_user(create_user_data)
    
#     client = APIClient()
#     client.force_authenticate(user=user)
#     url = reverse("user_profile_pic")
#     headers = {'Content-Type': 'application/json'}
#    # response = requests.post(url, json=test_create_Profile_Pic, headers=headers)

#     response = client.post(url,test_create_Profile_Pic  , headers=headers)
    
#     print(response.status_code)
    
   
#     response_data = response.json()
    
#     for key, value in test_create_Profile_Pic.items():
#         assert key in response_data
#         #assert response_data[key] == value
#         print(f"{key}: {response_data[key]}") 
    
#     assert response.status_code == 201'''




'''@patch('boto3.resource')
@pytest.mark.django_db
def test_reply_data(mocked_resource,client,post_data,create_user_data,blog_data,reply, random_data):
    test_comment_data(mocked_resource,client,post_data,create_user_data,blog_data,random_data)
   
   # Reply["Post"]=post_data_dic["post_id"]
    reply["Comments"]=Comments_data_dic["post_id"]
    reply["user"]=Comments_data_dic["user"]
    # password= bytes("jdfjdf")
    try:
        #user = CustomUser.objects.create_user(username="hdlac", password=str(random_data["password"]), email="asjdsj@gmail.com")

        user = CustomUser.objects.create_user(username = "hdlac" , password  = "12", email = "asjdsj@gmail.com")
        #print(f"Password: {random_data['password']}")
        client = APIClient()
        client.force_authenticate(user=user)
    except IntegrityError:
        print(f"Failed to create user with email address due to uniqueness constraint violation.")
    response = client.post("reply",reply)
    
    
    print({"response": response.content})
    
    print(response.status_code)
    
   
    response_data = response.json()
   
    # print(Comments)
    for key, value in reply.items():
        assert key in response_data
        assert response_data[key] == value
        print(f"{key}: {response_data[key]}")
         
    assert response.status_code == 200'''


