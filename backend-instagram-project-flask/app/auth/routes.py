from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import User
from werkzeug.security import check_password_hash

auth = Blueprint('auth', __name__, template_folder='auth_templates')



##############  API ROUTES ################
@auth.route('/api/signup', methods=["POST"])
def signMeUpAPI():

            data = request.json
            username = data['username']
            email = data['email']
            password = data['password']

            username_check = User.query.filter_by(username=username).first()
            email_check = User.query.filter_by(email=email).first()

            if username_check and email_check:
                return {
                    'status': 'not ok',
                    'message': 'That username AND email already belong to an acount.'
                    }
            elif username_check:
                return {
                    'status': 'not ok',
                    'message': 'That username already belongs to an acoount'
                    }  
            elif email_check:
                return {
                    'status': 'not ok',
                    'message': 'That email already belongs to an acoount'
                    }
            else:

                # Adding user to database/ instantiate someone new
                user = User(username, email, password)
                
                # Adding instance to SQL
                user.saveToDB()
                return {
                    'status': 'ok',
                    'message': 'Successfully created a user',
                }
               
@auth.route('/api/login', methods=["POST"])
def logMeInAPI():

    data = request.json
    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    if user:
        if check_password_hash(user.password, password):
            return {
                'status': 'ok',
                'message': f'Succesfully logged in. Welcome back, {user.username}!',
                'user': user.to_dict()
            }
            

        return {
            'status': 'not ok',
            'message': 'Incorrect password.'
        }

    return {
            'status': 'not ok',
            'message': 'A user with that username does not exist.'
        }


from ..apiauthhelper import basic_auth
@auth.route('/api/token', methods=["POST"])
@basic_auth.login_required
def getToken():
    user = basic_auth.current_user()
    return {    
                'status': 'ok',
                'message': f'Succesfully logged in. Welcome back!',
                'user': user.to_dict()
            }