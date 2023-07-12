from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
import re

auth = Blueprint('auth', __name__)


def has_special_characters(username):
    """
    Verifica se o nome de usuário contém caracteres especiais.
    Retorna True se contiver caracteres especiais, False caso contrário.
    """
    # Expressão regular para verificar se o nome de usuário contém apenas letras, números e underscore (_)
    username_pattern = r'^\w+$'

    return re.match(username_pattern, username) is None


def is_valid_email(email):
    """
    Verifica se o email fornecido é um email válido.
    Retorna True se o email for válido, False caso contrário.
    """
    # Expressão regular para verificar se o email é válido
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

    return re.match(email_pattern, email) is not None


def is_password_strong(password):
    """
    Verifica se a senha atende aos critérios de uma senha forte.
    Retorna True se a senha for forte, False caso contrário.
    """
    # Verificar o comprimento mínimo da senha
    if len(password) < 8:
        return False

    # Verificar se a senha contém pelo menos uma letra maiúscula
    if not re.search(r'[A-Z]', password):
        return False

    # Verificar se a senha contém pelo menos uma letra minúscula
    if not re.search(r'[a-z]', password):
        return False

    # Verificar se a senha contém pelo menos um número
    if not re.search(r'\d', password):
        return False

    # Verificar se a senha contém pelo menos um caractere especial
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False

    return True


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form.get('email_or_username')
        password = request.form.get('password')

        # Verificar se o email_or_username é um email válido
        is_email = is_valid_email(email_or_username)

        # Consultar o usuário com base no email ou nome de usuário fornecido
        if is_email:
            user = User.query.filter_by(email=email_or_username).first()
        else:
            user = User.query.filter_by(username=email_or_username).first()

        if user:
            if check_password_hash(user.password, password):
                flash('Login successful!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password!', category='error')
        else:
            flash('Invalid email or username.', category='error')

    return render_template('login.html', user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        user_username = User.query.filter_by(username=username).first()

        if user:
            flash('This email is already being used!', category='error')
        elif not is_valid_email(email):
            flash('Invalid email address!', category='error')
        elif user_username:
            flash('This username is already taken!', category='error')
        elif has_special_characters(username):
            flash('Username must not contain special characters!', category='error')
        elif len(username) < 2:
            flash('Username must be greater than 1 character.', category='error')
        elif password != password2:
            flash('Passwords don\'t match.', category='error')
        elif not is_password_strong(password):
            flash('Password is not strong enough.', category='error')
        else:
            new_user = User(email=email,  # type: ignore
                            username=username,  # type: ignore
                            password=generate_password_hash(password, method='scrypt'))  # type: ignore
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template('sign_up.html', user=current_user)
