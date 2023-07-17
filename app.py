import time

from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
import re
from random import *
from main import encryptTXTtoBin ,decryptTXTtoBin, key
import os
from flask_mail import Mail
from flask_mail import Message

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'marcass765@gmail.com'
app.config['MAIL_PASSWORD'] = 'usruuhxwrgmvpsse'
app.config['MAIL_DEFAULT_SENDER'] = ('donotrepely', 'donotreplay@gmail.com')

mail = Mail(app)
def deleteUser(userName):
    global s1,s2,s3,s4,d1,d2,d3,d4,link,userPass,information
    s1=s1.replace("\n"+userName+" "+d1[userName],"")
    s2=s2.replace("\n"+d1[userName]+" "+d2[d1[userName]],"")
    a=int(link[d1[userName]][0])
    b=int(link[d1[userName]][1])
    s3=s3.replace("\n"+link[d1[userName]][a+1]+" "+userPass[userName],"")
    s4=s4.replace("\n"+link[d1[userName]][b+1]+":"+d4[link[d1[userName]][b+1]],"")

def updateToDefaultfiles():
    s1="""karthik 6545
    abhinav 3154
    saiteja 6745
    chaitanya 9821"""

    s2="""6545 1 2 12 01 .
    3154 2 3 . 13 02
    6745 3 2 . 03 14
    9821 2 1 04 15 ."""

    s3="""12 kart123
    13 abhi345
    14 tej567
    15 chaitu901"""

    s4="""01:mvs karthik,09/02/2005,vijaysai.uchiha@gmail.com,male
    02:surabhi abhinav,15/12/2004,abhinavsurabhi@gmail.com,male
    03:k sai teja,07/10/2006,capstj@gmail.com,male
    04:chaitanya,16/05/2004,chaitanyagattu@gmail.com,female"""


    s1 = memoryview(s1.encode('utf-8')).tobytes()
    s2 = memoryview(s2.encode('utf-8')).tobytes()
    s3 = memoryview(s3.encode('utf-8')).tobytes()
    s4 = memoryview(s4.encode('utf-8')).tobytes()
    encryptTXTtoBin(s1,"encrypted.bin", key)
    encryptTXTtoBin(s2,"encrypted2.bin", key)
    encryptTXTtoBin(s3,"encrypted3.bin", key)
    encryptTXTtoBin(s4,"encrypted4.bin", key)

    s1 = decryptTXTtoBin("encrypted.bin",key)
    s2 = decryptTXTtoBin("encrypted2.bin",key)
    s3 = decryptTXTtoBin("encrypted3.bin",key)
    s4 = decryptTXTtoBin("encrypted4.bin",key)

    print(s1)
    print(s2)
    print(s3)
    print(s4)

def Reregister(username, password, Name, DateOfBirth, mail, gender):
    global s1, s2, s3, s4, d1, d2, d3, d4, userPass, information, infoKeys
    userPass[username] = password
    information[username] = {"name": Name, "dob": DateOfBirth, "mail": mail, "gender": gender}

    while (True):
        rand1 = str(randint(1000, 9999))
        if rand1 not in d1.keys():
            s1 = s1 + "\n" + username + " " + rand1
            break

    a = randint(1, 3)
    while (True):
        b = randint(1, 3)
        if a != b:
            break

    while (True):
        rand2 = str(randint(1000, 9999))
        rand3 = str(randint(1000, 9999))
        string = ''
        if rand2 not in d3.keys() and rand3 not in d4.keys():
            string = string + rand1 + " " + str(a) + " " + str(b) + " "
            for i in range(1, 4):
                if i == a:
                    string += rand2 + ' '
                elif i == b:
                    string += rand3 + ' '
                else:
                    string += str(randint(1, 1000)) + ' '
            break
    s2 += "\n" + string
    s3 += "\n" + rand2 + " " + password
    s4 += "\n" + rand3 + ":" + Name + "," + DateOfBirth + "," + mail + "," + gender

    d1[username] = rand1
    d2[rand1] = string
    d3[rand2] = password
    d4[rand3] = [Name, DateOfBirth, mail, gender]

    print(s1)
    print(s2)
    print(s3)
    print(s4)

    S1 = memoryview(s1.encode('utf-8')).tobytes()
    S2 = memoryview(s2.encode('utf-8')).tobytes()
    S3 = memoryview(s3.encode('utf-8')).tobytes()
    S4 = memoryview(s4.encode('utf-8')).tobytes()


    link = dict(zip(d2.keys(), (i.split() for i in d2.values())))

    infoKeys = {}
    for i, j in d1.items():
        infoKeys[i] = link[j][int(link[j][1]) + 1]

    encryptTXTtoBin(S1,"encrypted.bin", key)
    encryptTXTtoBin(S2,"encrypted2.bin", key)
    encryptTXTtoBin(S3,"encrypted3.bin", key)
    encryptTXTtoBin(S4,"encrypted4.bin", key)
def delENcALL(user):
    global s1, s2, s3, s4, d1, d2, d3, d4, userPass, information
    deleteUser(user)
    s1 = memoryview(s1.encode('utf-8')).tobytes()
    s2 = memoryview(s2.encode('utf-8')).tobytes()
    s3 = memoryview(s3.encode('utf-8')).tobytes()
    s4 = memoryview(s4.encode('utf-8')).tobytes()
    encryptTXTtoBin(s1,"encrypted.bin", key)
    encryptTXTtoBin(s2,"encrypted2.bin", key)
    encryptTXTtoBin(s3,"encrypted3.bin", key)
    encryptTXTtoBin(s4,"encrypted4.bin", key)




s1 = decryptTXTtoBin("encrypted.bin",key)
s2 = decryptTXTtoBin("encrypted2.bin",key)
s3 = decryptTXTtoBin("encrypted3.bin",key)
s4 = decryptTXTtoBin("encrypted4.bin",key)

# print(s1)
# print(s2)
# print(s3)
# print(s4)

d1 = dict([i.split() for i in s1.split("\n")])

d2 = dict([i.split(" ", maxsplit=1) for i in s2.split("\n")])

d3 = dict([i.split() for i in s3.split("\n")])

d4 = dict([i.split(":") for i in s4.split("\n")])

link = dict(zip(d2.keys(), (i.split() for i in d2.values())))

split = dict(zip(d4.keys(), (i.split(",") for i in d4.values())))

passKeys = {}
for i, j in d1.items():
    passKeys[i] = link[j][int(link[j][0]) + 1]

infoKeys = {}
for i, j in d1.items():
    infoKeys[i] = link[j][int(link[j][1]) + 1]

userPass = {}

for i in passKeys:
    userPass[i] = d3[passKeys[i]]

information = {}

for i in infoKeys.keys():
    dic = {}
    lis = d4[infoKeys[i]].split(",")
    dic["name"] = lis[0]
    dic["dob"] = lis[1]
    dic["mail"] = lis[2]
    dic["gender"] = lis[3]
    information[i] = dic


def validatePassword(s):
    return True
    if len(s) > 15 or len(s) < 5:
        return False
    else:
        return all(re.search(expression, s) for expression in ('[0-9]', '[A-Z]', '[a-z]', '[@#$%&]'))

def is_username_valid(username):
    if username and len(username) <= 20:
        if username not in userPass:
            return True
    return False

def get_uploaded_files(username):
    folder_path = os.path.join('uploads', infoKeys[username])
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return os.listdir(folder_path)

def generate_OTP():
    otp = ""
    for i in range(6):
        otp += str(randint(0,9))
    return otp
def get_uploaded_files_size(username):
    folder_path = os.path.join('uploads', infoKeys[username])
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    s =0
    for i in os.scandir(folder_path):
        s+= os.stat(i).st_size
    return s
def send_OTP(email):
    session['otp'] = generate_OTP()
    msg = Message('Email Verification', recipients=[email])
    msg.body = f'thanks for signing up! your OTP is:\n{session["otp"]}\nenter the otp to complete the signup process.'
    mail.send(msg)


@app.route('/', methods = ['GET'])
def index():
    if 'username' not in session:
        session['login-attempts'] = 0
        return render_template("home.html")

    username = session['username']

    files = get_uploaded_files(username)
    # file_path = []
    # for i in files:
    #     file_path.append('\\uploads'+'\\'+infoKeys[username]+"\\"+i)
    #
    # files_with_paths = list(zip(files, file_path))

    return render_template('welcome.html', files=files, username=username, abc=infoKeys[username])

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    return render_template('signup.html')


@app.route('/login_process', methods=['POST'])
def login_process():
    username = request.form['username']
    password = request.form['password']

    if username in userPass and password == userPass[username]:
        session['username'] = username
        return redirect(url_for('index'))
    else:
        session['login-attempts'] += 1
        return redirect(url_for('login'))

@app.route("/login/forgot_password")
def forgot_password():
    return render_template('forgot_password.html')

@app.route("/login/forgot_password/send_mail", methods=['GET', 'POST'])
def forgot_password_send_mail():
    email = request.form.get('email')
    msg = Message('Email Verification', recipients=[email])
    username = None
    for i in information:
        if information[i]['mail'] == email:
            username = i
    if username!= None:
        msg.body = f"here is your userid and password for login\nusename:{username}\npassword:{userPass[username]}\nignore if it wasnt you"
        mail.send(msg)
        return '''your login ID and Password is sent to mail
        <br><br>
        <a href="/login">home</a>
        '''
    else: return "invalid email"


@app.route('/signup_process', methods=['POST'])
def signup_process():
    name = request.form['name']
    username = request.form['username']
    password = request.form['password']
    cpassword = request.form['confirm-password']
    email = request.form['email']
    gender = request.form['gender']
    dob = request.form['dob']
    username_valid = is_username_valid(username)
    password_valid = validatePassword(password)

    if username_valid and password_valid and len(name) > 0 and password == cpassword:
        send_OTP(email)
        session['otp_sent_time'] = time.time()
        session['temp_info'] = [username, password, name, dob, email, gender]
        return redirect(url_for('otp'))
    error_message = ""
    if not username_valid:
        error_message += "Username is invalid. Please try a different one.\n"
    if not password_valid:
        error_message += "Password is invalid. It must have at least 8 characters, maximum 15 characters, and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.\n"
    if password != cpassword:
        error_message += "Passwords do not match.\n"

    return error_message

@app.route('/signup_process/otp', methods=['GET', 'POST'])
def otp():
    if 'temp_info' in session:
        error_message = request.args.get('error_message')
        return render_template('otp.html', expiry_time=get_remaining_expiry_time(), error_message=error_message)
    return redirect(url_for('signup'))

@app.route("/signup_process/otp/verify", methods = ['POST'])
def verifyOTP():
    if session['temp_info']:
        otp = request.form['otp']
        otp_sent_time = session.get('otp_sent_time', None)
        if otp_sent_time and (time.time() - otp_sent_time) > 300:
            session.pop('otp', None)
            error_message = "OTP has expired. Please request a new one."
            return redirect(url_for('otp', error_message=error_message))

        if otp == session['otp']:
            name = session['temp_info'][2]
            username = session['temp_info'][0]
            password = session['temp_info'][1]
            email = session['temp_info'][4]
            gender = session['temp_info'][5]
            dob = session['temp_info'][3]
            Reregister(username, password, name, dob, email, gender)
            session.pop('temp_info', None)
            session.pop('otp', None)
            return redirect(url_for('index'))
        else:
            error_message = "Incorrect OTP. Please try again."
            return redirect(url_for('otp', error_message = error_message))
    return redirect(url_for('signup'))
def get_remaining_expiry_time():
    otp_sent_time = session.get('otp_sent_time', None)
    if otp_sent_time:
        expiry_time = 300 - (time.time() - otp_sent_time)
        return int(expiry_time) if expiry_time > 0 else 0
    return 0

@app.route('/signup_process/otp/resend', methods=['POST'])
def resend_otp():
    email = session['temp_info'][4]
    send_OTP(email)
    session['otp_sent_time'] = time.time()
    # error_message = "OTP resent. Please check your email."
    return redirect(url_for('otp'))

@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    if 'username' not in session:

        return redirect(url_for('login'))

    username = session['username']

    files = get_uploaded_files(username)
    file_path = []
    for i in files:
        file_path.append(os.path.join('uploads', infoKeys[username], i))

    files_with_paths = list(zip(files, file_path))

    return render_template('welcome.html', files=files_with_paths)


@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    file = request.files['file']
    if file:
        filename = file.filename
        file.save(os.path.join('uploads', infoKeys[username], filename))
    return redirect(url_for('index'))

@app.route('/download')
def download():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    filename = request.args.get('filename')
    folder_path = os.path.join('uploads', infoKeys[username])
    return send_from_directory(folder_path, filename, as_attachment=True)

@app.route('/delete')
def delete():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    filename = request.args.get('filename')
    filepath = os.path.join('uploads', infoKeys[username], filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/about-us")
def aboutus():
    return render_template('aboutus.html')
@app.route("/feedback")
def feedback():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('feed back.html')
@app.route("/submit_feedback", methods=['POST'])
def submitFeedback():
    score = request.form.get('score')
    message = request.form.get('message')
    username = session['username']
    with open('feedback/feedback.txt','a') as fb:
        fb.write(score+","+username+","+message+"\n")
    return redirect(url_for('Thank'))
@app.route("/thankyou")
def Thank():
    return render_template('thankyou.html')

@app.route("/user-profile")
def profile():
    if "username" not in session:
        redirect(url_for('index'))
    username = session['username']
    name = information[username]["name"]
    dob = information[username]["dob"]
    mail = information[username]["mail"]
    gender = information[username]["gender"]
    no = len(get_uploaded_files(username))
    s = get_uploaded_files_size(username)/(1024*1024)
    s = str(round(s,2))+"Mb"
    return render_template('profile.html', username= username, name = name, dob =dob, email = mail, gender = gender,no = no, size = s )

def printfld(x):
    print(x)
if __name__ == '__main__':
    app.secret_key = b'\x96\xd7:5\\It\x03B\xcd\xdbQ}\x92\x91ci'
    app.run(host='0.0.0.0', port = 105, debug=True)
