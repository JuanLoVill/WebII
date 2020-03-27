# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers

#IMPORT LIBRARIRES/FUNCTIONS
#from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

def login(request):

    responseData = {}
    #VALIDATE METHOD
    if request.method == 'POST':

        #CHECK JSON STRUCTURE
        #CHECK JSON CONTENT
        is_Json = checkJson()

        if is_Json.isJson(request.body):
           jsonData = json.loads(request.body)
           attrError = False
           attrErrorMsg = ""
           if 'user' not in jsonData:
              attrError = True
              attrErrorMsg = "User is required"
           if 'password' not in jsonData:
              attrError = True
              attrErrorMsg = "Password is required"
           if attrError == True:
              responseData['result'] = 'error'
              responseData['message'] = attrErrorMsg
              return JsonResponse(responseData,status=401)
#CHECK IF USER EXITST
           try:
              loginUser = ApiUsers.objects.get(user = jsonData['user'])

           except:
              responseData['result'] = 'error'
              responseData['message'] = 'The user does not exist or the password is incorrect'
              return JsonResponse(responseData,status=401)
#TAKE PASSWORD OF THE USER
#CHECK IF PASSWORD IS CORRECT
           if check_password(jsonData['password'], loginUser.password):
#CHECK IF USER HAS API-KEY
              if loginUser.api_key == None:
                aux = ApiKey()
                apiKey = aux.generate_key_complex()
                loginUser.api_key = apiKey
                loginUser.save()
#RETURN RESPONSE
              responseData['result']= 'Success'
              responseData['message'] = 'Valid credentials'
              responseData['UserApiKey'] = loginUser.api_key
              return JsonResponse(responseData, status = 200)
           else:
               responseData['result'] = 'Error'
               responseData['message'] = 'The user does not exist or the password is incorrect'
               return JsonResponse(responseData, status = 401)



        else:
           responseData['result'] = 'error'
           responseData['message'] = 'Invalid Json'
           return JsonResponse(responseData,status=400) 


        

    else:
        responseData = {}
        responseData['result'] = 'error'
        responseData['message'] = 'Invalid Request'
        return JsonResponse(responseData, status=400)


def makepassword(request,password):
    hashPassword = make_password(password)
    response_data = {}
    response_data['password'] = hashPassword
    return JsonResponse(response_data, status=200)
