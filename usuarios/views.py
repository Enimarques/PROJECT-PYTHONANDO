from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.messages import constants
from django.contrib.auth import authenticate
from django.contrib import auth

 
def cadastro(request):
    if request.method == 'GET':
        return render(request, 'cadastro.html') 
    elif request.method == 'POST':
        username = request.POST.get('username')
        senha = request.POST.get('senha')
        confirmar_senha = request.POST.get('confirmar_senha')
        
        if senha != confirmar_senha:
            messages.add_message(request,constants.ERROR,'Senhas diferentes, não conferem')
            return redirect('/usuarios/cadastro/')
        
        if len(senha) < 6:
            messages.add_message(request,constants.ERROR,'A senha deve ter no mínimo 6 caracteres')
            return redirect('/usuarios/cadastro/')
        
        users = User.objects.filter(username=username) # Verifica se o usuário já existe
        if users.exists():
            messages.add_message(request,constants.ERROR,'Ja existe um usuario com esse username')
            return redirect('/usuarios/cadastro/')
        
        User.objects.create_user(
            username=username, 
            password=senha
            )
        
        return redirect('/usuarios/login/')
  
def login(request): #como eu criei a função com o nome login, vou usar o auth para não dar conflito com o nome do arquivo
    if request.method == 'GET':
        return render(request, 'login.html')
    elif request.method == 'POST':
        username = request.POST.get('username') #lembrando que eu puxo o "name" do input, devo procurar pelo name quando for fazer o post
        senha = request.POST.get('senha')
        
        user = authenticate(username=username, password=senha) #verifica se o usuario existe e se a senha ta certa (true ou none-false)
        if user:
            auth.login (request, user)
            return redirect('/mentorados/') 
        
        messages.add_message(request, constants.ERROR, 'Usuário ou senha inválidos')
        return redirect('login') #posso colocar só o nome da url que da certo
