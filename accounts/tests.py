'''from rest_framework.test import APIRequestFactory
# Using the standard RequestFactory API to create a form POST request
factory = APIRequestFactory()
request = factory.post('/notes/', {'title': 'new idea'})
#import unittest
from django.test import TestCase
from accounts.models import* 
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework import reverse
from django.contrib.auth import*
from mixer.backend.django import mixer
from django.utils.decorators import method_decorator

import pytest
from rest_framework.test import APIRequestFactory
from django.urls import reverse

@pytest.mark.django
def test_user_detail(django_CustomUser_model):
   user = django_CustomUser_model.objects.create(
       username='lokesh', password='123456'
   )
   url = reverse('user-detail-view', kwargs={'pk': user.pk})
   response = CustomUser.get(url)
   assert response.status_code == 200
   assert 'lokesh' in response.content
   assert '123456' in response.content
   

class Test_CustomUser_model(TestCase):
    def test_user_can_be_Register(self):
    
        user1 = mixer.blend(CustomUser, first_name="shiv",email = "shivpawar@gmail.com",password ="shivkumarpawar",last_name = "pawar",number = "9589544515")

        user_result = CustomUser.objects.last()  # getting the last user

        assert user_result.first_name == "shiv"
        assert user_result.last_name == "pawar"
        assert user_result.email == "shivpawar@gmail.com"
        assert user_result.password == "shivkumarpawar"
        assert user_result.number == "9589544515"
    def test_str_return(self):
    
        user1 = mixer.blend(CustomUser, first_name="shiv",last_name = "dfbgv53246542")

        user_result =CustomUser.objects.last()  # getting the last user
        
        assert str(user_result.first_name) == "shiv"
        assert str(user_result.last_name) == "pawar"
        
        print(" Register Method status code for Success:")

class Test_CustomUser_model(TestCase):
    def test_user_can_be_login(self):
    
        user1 = mixer.blend(CustomUser,email = "shivpawar@gmail.com",password ="123456")

        user_result = CustomUser.objects.last()  # getting the last user

        assert user_result.email== "shivpawar@gmail.com"
        assert user_result.password == "123456"
    def test_str_return(self):
    
        user1 = mixer.blend(CustomUser, email = "shivpawar@gmail.com")

        user_result =CustomUser .objects.last()  # getting the last user

        assert str(user_result.email) == "shivpawar@gmail.com"
        print("login POST Method status code for Success:")

class Test_CustomUser_model(TestCase):
    def test_user_can_be_ChangePassword(self):
    
        user1 = mixer.blend(CustomUser,email = "shivpawar@gmail.com",password ="shivkumarpawar",new_password = '123456')

        user_result = CustomUser.objects.last()  # getting the last user

        assert user_result.email == "shivpawar@gmail.com"
        assert user_result.email == "shivpawar@gmail.com"
        assert user_result.email == "shivpawar@gmail.com"
       
    def test_str_return(self):
    
        user1 = mixer.blend(CustomUser,email = "shivpawar@gmail.com",password ="shivkumarpawar",new_password = '123456')

        user_result =CustomUser.objects.last()  # getting the last user

        assert str(user_result.email) == "shivpawar@gmail.com"
        print("ChangePassword POST Method status code for Success:")

class Test_CustomUser_model(TestCase):
    def test_user_can_be_Forget_password(self):

        user1 = mixer.blend(CustomUser,username = 'shivpawar' ,email = "shivpawar@gmail.com",password ="shivkumarpawar",new_password = '123456')

        user_result = CustomUser.objects.last()  # getting the last user

        assert user_result.email == "shivpawar@gmail.com"
        assert user_result.username == "shivpawar"
       
    def test_str_return(self):
    
        user1 = mixer.blend(CustomUser, email = "shivpawar@gmail.com",username = "shivpawar")

        user_result =CustomUser.objects.last()  # getting the last user

        assert str(user_result.email) == "shivpawar@gmail.com"
        assert user_result.username == "shivpawar"
        print("Forget_password POST Method status code for Success:")

class Test_Post_model(TestCase):
    def test_user_can_be_Post(self):
        user1 = mixer.blend(Post, post_name = "googal",tag_name = "python",post_header = "python devloper",post_content = "fullstace devloper")

        user_result = Post.objects.last()  # getting the last user

        assert user_result.post_name == "googal"
        assert user_result.tag_name == "python"
        assert user_result.post_header == "python devloper"
        assert user_result.post_content == "fullstace devloper"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Post, post_name = "googal",tag_name = 'python',post_header = "python devloper",post_content = "fullstace devloper")

        user_result =Post.objects.last()  # getting the last user
        
        assert str(user_result.post_name) == "googal"
        assert str(user_result.tag_name) == "python"
        assert str(user_result.post_header) == "python devloper"
        assert str(user_result.post_content) == "fullstace devloper"
        print("user  POST  status code for Success")

    def test_user_can_be_Post_get(self):

        user1 = mixer.blend(Post, post_name = "googal",tag_name = "python",post_header = "python devloper",post_content = "fullstace devloper")

        user_result = Post.objects.last()  # getting the last user

        assert user_result.post_name == "googal"
        assert user_result.tag_name == "python"
        assert user_result.post_header == "python devloper"
        assert user_result.post_content == "fullstace devloper"
        
        
    def test_str_return(self):
    
        user1 = mixer.blend(Post, post_name = "googal",tag_name = 'python',post_header = "python devloper",post_content = "fullstace devloper")

        user_result =Post.objects.last()  # getting the last user
        
        assert str(user_result.post_name) == "googal"
        assert str(user_result.tag_name) == "python"
        assert str(user_result.post_header) == "python devloper"
        assert str(user_result.post_content) == "fullstace devloper"
        print("user Get all  POST  status code for Success")
    
    def test_user_can_be_Post_update(self):
    
        user1 = mixer.blend(Post, post_name = "googal",tag_name = "python",post_header = "python devloper",post_content = "fullstace devloper")

        user_result = Post.objects.last()  # getting the last user

        assert user_result.post_name == "googal"
        assert user_result.tag_name == "python"
        assert user_result.post_header == "python devloper"
        assert user_result.post_content == "fullstace devloper"
       
    def test_str_return(self):
    
        user1 = mixer.blend(Post, post_name = "googal",tag_name = 'python',post_header = "python devloper",post_content = "fullstace devloper")

        user_result =Post.objects.last()  # getting the last user
        
        assert str(user_result.post_name) == "googal"
        assert str(user_result.tag_name) == "python"
        assert str(user_result.post_header) == "python devloper"
        assert str(user_result.post_content) == "fullstace devloper"
        
        print("user update all  POST  status code for Success")

class Test_Social_model(TestCase):
    def test_user_can_be_Social_post(self):
        user1 = mixer.blend(Social, linkedin = "googal",twitter = "python",instagram = "food",facebook = "python devloper")

        user_result = Social.objects.last()  # getting the last user

        assert user_result.linkedin == "googal"
        assert user_result.twitter == "python"
        assert user_result.instagram == "food"
        assert user_result.facebook == "python devloper"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Social, linkedin = "googal",twitter = "python",instagram = "food",facebook = "python devloper")

        user_result =Social.objects.last()  # getting the last user
        
        assert str(user_result.linkedin) == "googal"
        assert str(user_result.twitter) == "python"
        assert str(user_result.instagram) == "food"
        assert str(user_result.facebook) == "python devloper"
        print("user Social POST  status code for Success")

    def test_user_can_be_Social_get(self):
        user1 = mixer.blend(Social, linkedin = "googal",twitter = "python",instagram = "food",facebook = "python devloper")

        user_result = Social.objects.last()  # getting the last user

        assert user_result.linkedin == "googal"
        assert user_result.twitter == "python"
        assert user_result.instagram == "food"
        assert user_result.facebook == "python devloper"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Social, linkedin = "googal",twitter = "python",instagram = "food",facebook = "python devloper")

        user_result =Social.objects.last()  # getting the last user
        
        assert str(user_result.linkedin) == "googal"
        assert str(user_result.twitter) == "python"
        assert str(user_result.instagram) == "food"
        assert str(user_result.facebook) == "python devloper"
        print("user Social get  status code for Success")

    def test_user_can_be_Social_update(self):
        user1 = mixer.blend(Social, linkedin = "jobportel",twitter = "pichers",instagram = "abcd",facebook = "python devloper")

        user_result = Social.objects.last()  # getting the last user

        assert user_result.linkedin == "jobportel"
        assert user_result.twitter == "pichers"
        assert user_result.instagram == "abcd"
        assert user_result.facebook == "python devloper"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Social, linkedin = "jobportel",twitter = "pichers",instagram = "abcd",facebook = "python devloper")

        user_result =Social.objects.last()  # getting the last user
        
        assert str(user_result.linkedin) == "jobportel"
        assert str(user_result.twitter) == "pichers"
        assert str(user_result.instagram) == "abcd"
        assert str(user_result.facebook) == "python devloper"
        print("user  POST  status code for Success")
    
class Test_About_model(TestCase):
    def test_user_can_be_About_post(self):
        user1 = mixer.blend(About,description = "googal is most popular brouser", location = "plasiya indor",email = "lokeshkaushik2509@gmail.com",workad_at = "python devloper",Studied_at = "btec student")

        user_result = About.objects.last()  # getting the last user

        assert user_result.description == "googal is most popular brouser"
        assert user_result.location == "plasiya indor"
        assert user_result.email == "lokeshkaushik2509@gmail.com"
        assert user_result.workad_at == "python devloper"
        assert user_result.Studied_at == "btec student"
    def test_str_return(self):
    
        user1 = mixer.blend(About,description = "googal is most popular brouser", location = "plasiya indor",email = "lokeshkaushik2509@gmail.com",workad_at = "python devloper",Studied_at = "btec student")

        user_result =About.objects.last()  # getting the last user
        
        assert str(user_result.description) == "googal is most popular brouser"
        assert str(user_result.location) == "plasiya indor"
        assert str(user_result.email) == "lokeshkaushik2509@gmail.com"
        assert str(user_result.workad_at) == "python devloper"
        assert str(user_result.Studied_at) == "btec student"
        print("user About POST status code for Success")

    def test_user_can_be_About_get(self):
        user1 = mixer.blend(About,description = "googal is most popular brouser", location = "plasiya indor",email = "lokeshkaushik2509@gmail.com",workad_at = "python devloper",Studied_at = "btec student")

        user_result = About.objects.last()  # getting the last user

        assert user_result.description == "googal is most popular brouser"
        assert user_result.location == "plasiya indor"
        assert user_result.email == "lokeshkaushik2509@gmail.com"
        assert user_result.workad_at == "python devloper"
        assert user_result.Studied_at == "btec student"
    def test_str_return(self):
    
        user1 = mixer.blend(About,description = "googal is most popular brouser", location = "plasiya indor",email = "lokeshkaushik2509@gmail.com",workad_at = "python devloper",Studied_at = "btec student")

        user_result =About.objects.last()  # getting the last user
        
        assert str(user_result.description) == "googal is most popular brouser"
        assert str(user_result.location) == "plasiya indor"
        assert str(user_result.email) == "lokeshkaushik2509@gmail.com"
        assert str(user_result.workad_at) == "python devloper"
        assert str(user_result.Studied_at) == "btec student"
        print("user About get status code for Success")
  

    def test_user_can_be_About_update(self):
        user1 = mixer.blend(About,description = "googal best popular", location = "plasiya indor",email = "lokeshkaushik1222@gmail.com",workad_at = "django devloper",Studied_at = "btec student")

        user_result = About.objects.last()  # getting the last user

        assert user_result.description == "googal best popular"
        assert user_result.location == "plasiya indor"
        assert user_result.email == "lokeshkaushik1222@gmail.com"
        assert user_result.workad_at == "django devloper"
        assert user_result.Studied_at == "btec student"
    def test_str_return(self):
    
        user1 = mixer.blend(About,description = "googal best popular", location = "plasiya indor",email = "lokeshkaushik1222@gmail.com",workad_at = "django devloper",Studied_at = "btec student")

        user_result =About.objects.last()  # getting the last user
        
        assert str(user_result.description) == "googal best popular"
        assert str(user_result.email) == "lokeshkaushik1222@gmail.com"
        assert str(user_result.workad_at) == "django devloper"
        assert str(user_result.Studied_at) == "btec student"
        assert str(user_result.location) == "plasiya indor"
        print("user About update status code for Success") 

class Test_Profile_Pic_model(TestCase):
    def test_user_can_be_Profile_Pic_post(self):
        user1 = mixer.blend(Profile_Pic,background_image = "abc.jpg",images = "xyz.jpg",Post = "googal")

        user_result = Profile_Pic.objects.last()  # getting the last user

        assert user_result.background_image == "abc.jpg"
        assert user_result.images == "xyz.jpg"
        #assert user_result.Post == "googal"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Profile_Pic,background_image = "abc.jpg",images = "xyz.jpg")

        user_result =Profile_Pic.objects.last()  # getting the last user
        
        assert str(user_result.background_image) == "abc.jpg"
        assert str(user_result.images) == "xyz.jpg"
        print("user Profile_Pic POST status code for Success")

    def test_user_can_be_Profile_Pic_get(self):
        user1 = mixer.blend(Profile_Pic,background_image = "abc.jpg",images = "xyz.jpg",Post = "googal")

        user_result = Profile_Pic.objects.last()  # getting the last user

        assert user_result.background_image == "abc.jpg"
        assert user_result.images == "xyz.jpg"

    def test_str_return(self):
        
        user1 = mixer.blend(Profile_Pic,background_image = "abc.jpg",images = "xyz.jpg")

        user_result =Profile_Pic.objects.last()  # getting the last user
        
        assert str(user_result.background_image) == "abc.jpg"
        assert str(user_result.images) == "xyz.jpg"
        print("user Profile_Pic get status code for Success")  
  
    def test_user_can_be_Profile_Pic_update(self):
        user1 = mixer.blend(Profile_Pic,background_image = "jhjhkj.jpg",images = "jhgjhg.jpg",Post = "googal")

        user_result = Profile_Pic.objects.last()  # getting the last user

        assert user_result.background_image == "jhjhkj.jpg"
        assert user_result.images == "jhgjhg.jpg"

    def test_str_return(self):
        
        user1 = mixer.blend(Profile_Pic,background_image = "jhjhkj.jpg",images = "jhgjhg.jpg")

        user_result =Profile_Pic.objects.last()  # getting the last user
        
        assert str(user_result.background_image) == "jhjhkj.jpg"
        assert str(user_result.images) == "jhgjhg.jpg"
        print("user Profile_Pic get status code for Success") 
  
class Test_Comments_model(TestCase):
    def test_user_can_be_Comments_post(self):
        user1 = mixer.blend(Comments,text= "comments is a every blog post in a comment")

        user_result = Comments.objects.last()  # getting the last user

        assert user_result.text == "comments is a every blog post in a comment"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Comments,text= "comments is a every blog post in a comment")

        user_result =Comments.objects.last()  # getting the last user
        
        assert str(user_result.text) == "comments is a every blog post in a comment"
        
        print("user Comments POST status code for Success")

    def test_user_can_be_Comments_get(self):
        user1 = mixer.blend(Comments,text= "comments is a every blog post in a comment" )

        user_result = Comments.objects.last()  # getting the last user

        assert user_result.text == "comments is a every blog post in a comment"

        
        
    def test_str_return(self):
    
        user1 = mixer.blend(Comments,text= "comments is a every blog post in a comment")

        user_result =Comments.objects.last()  # getting the last user
        
        assert str(user_result.text) == "comments is a every blog post in a comment"
        
        print("user Comments get status code for Success")

    def test_user_can_be_Comments_update(self):
        user1 = mixer.blend(Comments,text= "comments is a basecaly use in python" )

        user_result = Comments.objects.last()  # getting the last user

        assert user_result.text == "comments is a basecaly use in python"

        
        
    def test_str_return(self):
    
        user1 = mixer.blend(Comments,text= "comments is a basecaly use in python")

        user_result =Comments.objects.last()  # getting the last user
        
        assert str(user_result.text) == "comments is a basecaly use in python"
        
        print("user Comments update status code for Success")

def Comments_delete(APITestCase):
    def test_delete_method_success(self):
        url="http://127.0.0.1:8000/Comments_delete/1/"
        response=self.client.delete(id=id) 
        self.assertEqual(response.status_code,401)
        print("DELETE Method status code for Success:",response.status_code)

    def test_delete_method_fail(self):
        url="http://127.0.0.1:8000/Comments_delete/1/"
        response=self.client.delete(format='json')
        self.assertEqual(response.status_code,401)
        print("DELETE Method status code for Success:",response.status_code)'''
    

'''class Test_Reply_model(TestCase):
    def test_user_can_be_Reply_post(self):
        user1 = mixer.blend(Reply,content = "this is a blog replay")

        user_result = Reply.objects.last()  # getting the last user
        assert user_result.content == "this is a blog replay"

    def test_str_return(self):
    
        user1 = mixer.blend(Reply,content = "this is a blog replay")

        user_result =Reply.objects.last()  # getting the last user
        
        assert str(user_result.content) == "this is a blog replay"

        print("user Rplay POST status code for Success")

    def test_user_can_be_Reply_get(self):
        user1 = mixer.blend(Reply,content = "this is a blog replay")

        user_result = Reply.objects.last()  # getting the last user
        assert user_result.content == "this is a blog replay"

    def test_str_return(self):
    
        user1 = mixer.blend(Reply,content = "this is a blog replay")

        user_result =Reply.objects.last()  # getting the last user
        
        assert str(user_result.content) == "this is a blog replay"

        print("user Rplay get status code for Success")    

    def test_user_can_be_Reply_update(self):
        user1 = mixer.blend(Reply,content = "this blog is a comment replay")

        user_result = Reply.objects.last()  # getting the last user
        assert user_result.content == "this blog is a comment replay"

    def test_str_return(self):
    
        user1 = mixer.blend(Reply,content ="this blog is a comment replay")

        user_result =Reply.objects.last()  # getting the last user
        
        assert str(user_result.content) == "this blog is a comment replay"

        print("user Rplay update status code for Success")   

class Test_Post_model(TestCase):
    def test_user_can_be_Post_get(self):
    
        user1 = mixer.blend(Post, post_name = "googal",tag_name = "python",post_header = "python devloper",post_content = "fullstace devloper")

        user_result = Post.objects.last()  # getting the last user

        assert user_result.post_name == "googal"
        assert user_result.tag_name == "python"
        assert user_result.post_header == "python devloper"
        assert user_result.post_content == "fullstace devloper"
        
        
    def test_str_return(self):
    
        user1 = mixer.blend(Post, post_name = "googal",tag_name = 'python',post_header = "python devloper",post_content = "fullstace devloper")

        user_result =Post.objects.last()  # getting the last user
        
        assert str(user_result.post_name) == "googal"
        assert str(user_result.tag_name) == "python"
        assert str(user_result.post_header) == "python devloper"
        assert str(user_result.post_content) == "fullstace devloper"
        print("user Get all  POST  status code for Success")'''

'''def test_reply_delete(APITestCase):
    def test_reply_delete_method_success(self):
        url="http://127.0.0.1:8000/reply_delete/1/"
        _response=self.client.delete(id=id)
        self.assertEqual(_response.status_code,204)
        print("DELETE Method status code for Success:",_response.status_code)

    def test_delete_method_fail(self):
        url="http://127.0.0.1:8000/reply_delete/1/"
        response=self.client.delete(pk=id)
        self.assertEqual(response.status_code,404)
        print("DELETE Method status code for fail:",response.status_code)'''

    

'''class Test_Blog_model(TestCase):
    def test_user_can_be_Blog_post(self):
        user1 = mixer.blend(Blog,blog_name = "this post is a popular post",tag_name = "python",blog = "food",is_approved = "True",images = "hjkj.jpg")

        user_result = Blog.objects.last()  # getting the last user
        assert user_result.blog_name == "this post is a popular post"
        assert user_result.tag_name == "python"
        assert user_result.images == "hjkj.jpg"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Blog,blog_name = "this post is a popular post",tag_name = "python",images = "hjkj.jpg")

        user_result =Blog.objects.last()  # getting the last user
        
        assert str(user_result.blog_name) == "this post is a popular post"
        assert str(user_result.tag_name) == "python"
        assert str(user_result.images) == "hjkj.jpg"
        
        print("user blog POST status code for Success")

    def test_user_can_be_Blog_get(self):
        user1 = mixer.blend(Blog,blog_name = "this post is a popular post",tag_name = "python",blog = "food",is_approved = "True",images = "hjkj.jpg")

        user_result = Blog.objects.last()  # getting the last user
        assert user_result.blog_name == "this post is a popular post"
        assert user_result.tag_name == "python"
        assert user_result.images == "hjkj.jpg"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Blog,blog_name = "this post is a popular post",tag_name = "python",is_approved = "True",images = "hjkj.jpg")

        user_result =Blog.objects.last()  # getting the last user
        
        assert str(user_result.blog_name) == "this post is a popular post"
        assert str(user_result.tag_name) == "python"
        assert str(user_result.is_approved) == "True"
        assert str(user_result.images) == "hjkj.jpg"
        print("user blog get status code for Success")

    def test_user_can_be_Blog_update(self):
        user1 = mixer.blend(Blog,blog_name = "this blog  post is a user creat post",tag_name = "python",blog = "food",is_approved = "True",images = "hjkj.jpg")

        user_result = Blog.objects.last()  # getting the last user
        assert user_result.blog_name == "this blog  post is a user creat post"
        assert user_result.tag_name == "python"
        assert user_result.images == "hjkj.jpg"
        
    def test_str_return(self):
    
        user1 = mixer.blend(Blog,blog_name = "this blog  post is a user creat post",tag_name = "python",is_approved = "True",images = "hjkj.jpg")

        user_result =Blog.objects.last()  # getting the last user
        
        assert str(user_result.blog_name) == "this blog  post is a user creat post"
        assert str(user_result.tag_name) == "python"
        assert str(user_result.is_approved) == "True"
        assert str(user_result.images) == "hjkj.jpg"
        print("user blog update status code for Success")

class test_Blog_delete(APITestCase):
    def test_delete_method_success(self):
        url="http://127.0.0.1:8000/blog_delete/1/"
        _response=self.client.delete(url,format='json')
        self.assertEqual(_response.status_code,401)
        print("DELETE Method status code for Success:",_response.status_code)
    def test_delete_method_fail(self):
        url="http://127.0.0.1:8000/blog_delete/1/"
        _response=self.client.delete(url)
        self.assertEqual(_response.status_code,401)
        print("DELETE Method status code for Success:",_response.status_code)

class Test_Video_model(APITestCase):
    def test_user_can_be_video_post(self):
        user1 = mixer.blend(Video,video = "abcde")

        user_result = Video.objects.last()  # getting the last user
        assert user_result.video == "abcde"
    def test_str_return(self):
    
        user1 = mixer.blend(Video,video = "abcde")

        user_result =Video.objects.last()  # getting the last user
        
        assert str(user_result.video) == "abcde"
        print("user blog POST status code for Success")

class CategoryListView(APITestCase):
    def test_get_method_success(self):
        url="http://127.0.0.1:8000/Category/"
        _response=self.client.get(url)
        self.assertEqual(_response.status_code,200)
        qs=Blog.objects.filter(tag_name='python')
        self.assertEqual(qs.count(),0,True)
        print("GET Method status code for Success:",_response.status_code)
    
    def test_get_method_fail(self):
        url="http://127.0.0.1:8000/Category/"
        response=self.client.get(url)
        self.assertEqual(response.status_code,200)
        qs=Post.objects.filter(tag_name='googal')
        self.assertEqual(qs.count(),0,False)
        print("GET Method status code for Fail:",response.status_code)'''
      
