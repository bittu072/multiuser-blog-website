# Multi User Blog
***
### Introduction
This is a project of "Multi User Blog" website. The project is to create server side code backedn code to create a website that allows user to sign up, login and post blogs. User can also comment and like the post.
### Features
* Written in Pyhton, HTML, CSS
* Hosted on Google cloud (google app engine)

### What's included
```
project_Movie_Trailer/
  |-- static
        |-- css
                |-- blogstyle.css
                |-- bootsrap.min.css
                |-- style.css
        |-- js
                |-- bootstrap.min.js
                |-- jquery-3.1.0.js
  |-- templates
        |-- allblog.html
        |-- base.html
        |-- base2.html
        |-- blogedit.html
        |-- bloghome.html
        |-- blognew.html
        |-- blogpage.html
        |-- firstpage.html
        |-- login.html
        |-- post.html
        |-- signup.html
        |-- welcome.html
  |-- app.yaml
  |-- blogweb.py
  |--index.yaml
```

### Requirement:
google app engine, python module (os, re, jinja2, webapp2, random, hashlib, hmac) , gcloud (if you want to run it live)

### Instruction:
* Clone or download this repo
* Install google app engine and add it to your environment path
* Main file for back-end is blogweb.py so if you want to make changes, edit this file.
* app.yaml has all the app define and describe with static files.
* Run this web app,
  * To run it locally, 
      1. open terminal
      2. type ` dev_appserver.py .`
  * To run it online live,
      1. Go to the project main directory (where app.yaml is located)
      2. open terminal
      3. type `gcloud app deploy`
      4. type `gcloud app browse`

