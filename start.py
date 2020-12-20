import datetime

import redis

from flask import Flask, render_template, redirect, flash, request, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, DECIMAL, TEXT, DateTime, ARRAY, BOOLEAN, null, func
from flask_login import LoginManager, login_user, logout_user, current_user
from sqlalchemy_utils import aggregated
from werkzeug.security import generate_password_hash, check_password_hash
from flask_user import roles_required, UserManager, SQLAlchemyAdapter, UserMixin, login_required

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
manager = LoginManager(app)
r = redis.Redis()
username = r.get("username").decode("utf_8")
password = r.get("password").decode("utf_8")
secret_key = r.get('secret').decode("utf_8")
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://' + username + ':' + password + '@localhost:3306/it_db_cp_2'
app.secret_key = secret_key
db1 = SQLAlchemy(app)

db1.create_all()


class Users(db1.Model, UserMixin):
    __tablename__ = "users"
    id = db1.Column(Integer, primary_key=True)
    login = db1.Column(String(130), nullable=False)
    first_name = db1.Column(String(50), nullable=False)
    last_name = db1.Column(String(50), nullable=False)
    password = db1.Column(String(255), nullable=False)
    month_pay = db1.Column(DECIMAL(15, 2), nullable=False, default=0.0)
    roles = db1.relationship('Roles', secondary='user_roles', backref=db1.backref('users', lazy='dynamic'))

    def __repr__(self):
        return '<User %r>' % self.id


class Roles(db1.Model):
    __tablename__ = 'roles'
    id = db1.Column(Integer, primary_key=True)
    name = db1.Column(String(50), nullable=False, unique=True)


class UserRoles(db1.Model):
    __tablename__ = 'user_roles'
    id = db1.Column(Integer, primary_key=True)
    user_id = db1.Column(Integer, db1.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db1.Column(Integer, db1.ForeignKey('roles.id', ondelete='CASCADE'))


class Tariff(db1.Model):
    __tablename__ = "tariffs"
    id = db1.Column(Integer, primary_key=True)
    parking_place_price = db1.Column(DECIMAL(15, 2), nullable=False)
    water_tariff = db1.Column(DECIMAL(15, 2), nullable=False)
    gas_tariff = db1.Column(DECIMAL(15, 2), nullable=False)
    electricity_tariff = db1.Column(DECIMAL(15, 2), nullable=False)
    description = db1.Column(TEXT, nullable=False)

    def __repr__(self):
        return '<Tariff %r>' % self.id


class Contract(db1.Model):
    __tablename__ = 'contracts'
    id = db1.Column(Integer, primary_key=True)
    user_id = db1.Column(Integer, db1.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    tariff_id = db1.Column(Integer, db1.ForeignKey('tariffs.id', ondelete='CASCADE'), nullable=False)
    create_date = db1.Column(DateTime, default=datetime.datetime.utcnow())
    registered_cars = db1.Column(ARRAY(String(50)))

    def __repr__(self):
        return '<Contract %r>' % self.id


class Parking_place(db1.Model):
    __tablename__ = 'parking_places'
    id = db1.Column(Integer, primary_key=True)
    is_occupied = db1.Column(BOOLEAN, nullable=False)
    contract_id = db1.Column(Integer, db1.ForeignKey('contracts.id', ondelete='SET NULL'))

    def __repr__(self):
        return '<Contract %r>' % self.id


class Malfunction(db1.Model):
    __tablename__ = 'malfunctions'
    id = db1.Column(Integer, primary_key=True)
    fix_price = db1.Column(DECIMAL(15, 2), nullable=False)
    is_payed = db1.Column(BOOLEAN, nullable=False, default=0)
    description = db1.Column(TEXT, nullable=False)
    user_id = db1.Column(Integer, db1.ForeignKey('users.id', ondelete='NO ACTION'))

    def __repr__(self):
        return '<Malfunction %r>' % self.id


db1.create_all()
db_adapter = SQLAlchemyAdapter(db1, Users)
user_manager = UserManager(db_adapter, app)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404_error.html'), 404


@app.route('/home')
@app.route('/', methods=['GET'])
def index():
    return render_template("index.html", id=current_user.get_id())


@app.route('/users')
@login_required
@roles_required(['Admin'])
def all_users():
    print(current_user.get_id())
    users = Users.query.order_by(Users.first_name).all()
    return render_template("users.html", users=users)


@app.route('/users/<int:id>', methods=["GET"])
@login_required
def detailed_user(id):
    if id is None:
        return url_for(login_required())
    else:
        user = Users.query.get_or_404(id)
        return render_template("user_detail.html", user=user)


@app.route('/users/<int:id>/delete')
@login_required
def user_delete(id):
    user = Users.query.get_or_404(id)
    try:
        db1.session.delete(user)
        db1.session.commit()
        return redirect("/users")
    except:
        return "Error on deleting this user"


@app.route('/users/<int:id>/update', methods=['POST', 'GET'])
@login_required
def user_update(id):
    user = Users.query.get_or_404(id)
    if request.method == "POST":
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        try:
            db1.session.commit()
            return redirect('/users')
        except:
            return "Error on user update"

    else:
        return render_template("user_update.html", user=user)


# добавить валидацию
@app.route("/login", methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = Users.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get("next")
            redirect(next_page)
        else:
            flash('Login or password is not correct')

    else:
        flash('Please fill login and password fields')
    print(current_user.get_id())
    return render_template("login.html")


# добавить валидацию
@app.route("/register", methods=['GET', 'POST'])
def register():
    roles = Roles.query.all()
    role = request.form.get('role')
    print(role)
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    role = request.form.get('role')

    if request.method == 'POST':
        if Users.query.filter_by(login=login).count()==1:
            flash('please select another login')
        if not (login or password or password2 or first_name or last_name):
            flash("Please fill all fields")
        elif password != password2:
            flash("passwords are not equal")
        else:
            hash_pwd = generate_password_hash(password)
            new_user = Users(login=login, password=hash_pwd, first_name=first_name, last_name=last_name)
            db1.session.add(new_user)
            db1.session.commit()
            if role == '1':
                new_u_r_relation = UserRoles(user_id=new_user.id, role_id=1)
                db1.session.add(new_u_r_relation)
                db1.session.add(new_u_r_relation)
                db1.session.commit()
                return redirect(url_for('login_page'))
            elif role == '2':
                new_u_r_relation = UserRoles(user_id=new_user.id, role_id=1)
                new_u_r_relation_1 = UserRoles(user_id=new_user.id, role_id=2)
                db1.session.add(new_u_r_relation_1)
                db1.session.add(new_u_r_relation)
                db1.session.commit()
                return redirect(url_for('login_page'))


    return render_template('register.html', roles=roles)


@app.route('/users/None')
def no_registration():
    return redirect(url_for('login_page'))


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next' + request.url)
    return response


@manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route('/tariffs', methods=['GET'])
def all_tariffs():
    all_tariffs = Tariff.query.order_by(Tariff.id).all()
    # print(all_tariffs)
    return render_template('tariffs.html', tariffs=all_tariffs)


# добавить верхнюю границу
@app.route('/tariffs/<int:id>/update', methods=['GET', 'POST'])
@login_required
@roles_required(['Admin'])
def tariff_update(id):
    tariff = Tariff.query.get_or_404(id)
    if request.method == "POST":
        tariff.parking_place_price = request.form.get('parking_place_price')
        tariff.water_tariff = request.form.get('water_tariff')
        tariff.gas_tariff = request.form.get('gas_tariff')
        tariff.electricity_tariff = request.form.get('electricity_tariff')
        if (float(tariff.electricity_tariff) < 0 or
                float(tariff.parking_place_price) < 0 or
                float(tariff.gas_tariff) < 0 or
                float(tariff.water_tariff) < 0):
            flash("Incorrect data in fields")
            return render_template('tariff_update.html', tariff=tariff)
        else:
            try:
                db1.session.commit()
                return redirect('/tariffs')
            except:
                return "Error on tariff update"

    else:
        return render_template("tariff_update.html", tariff=tariff)


@app.route('/users/<int:id>/contract', methods=['GET', 'POST'])
def contract_check(id):
    contract = Contract.query.filter_by(user_id=id).first()
    if contract:
        print('contract found')
        return redirect(url_for('detailed_contract', id=contract.id))
    else:
        print('cant find such contract')
        return redirect(url_for('create_contract'))


# добавить валидацию
@app.route('/create_contract', methods=['GET', 'POST'])
@login_required
def create_contract():
    empty_parking_places = Parking_place.query.filter_by(is_occupied=0).all()
    user_id = current_user.get_id()
    # сюда
    registered_cars = request.form.get('registered_cars')
    tariff = request.form.get('tariff_type')
    parking_place_id = request.form.get('parking_place_number')
    if request.method == 'POST':
        if not registered_cars:
            flash('Fill all fields')
        else:
            if tariff == 'common':
                new_contract = Contract(user_id=user_id, registered_cars=registered_cars, tariff_id=1)
                # return render_template('/users/' + user_id)
                db1.session.add(new_contract)
                db1.session.commit()
                pp = Parking_place.query.get(parking_place_id)
                pp.is_occupied = 1
                pp.contract_id = new_contract.id
                db1.session.commit()
                db1.session.commit()
                return redirect(url_for('detailed_user', id=user_id))
            elif tariff == 'extended':
                new_contract = Contract(user_id=user_id, registered_cars=registered_cars, tariff_id=2)
                db1.session.add(new_contract)
                db1.session.commit()
                return redirect(url_for('detailed_user', id=user_id))
            elif tariff == 'premium':
                new_contract = Contract(user_id=user_id, registered_cars=registered_cars, tariff_id=3)
                db1.session.add(new_contract)
                db1.session.commit()
                return redirect(url_for('detailed_user', id=user_id))
    return render_template('create_contract.html', id=user_id, parking_places=empty_parking_places)


@app.route('/contracts')
@login_required
@roles_required(['Admin'])
def all_contracts():
    all_contracts = Contract.query.order_by(Contract.id).all()
    all_occupied_places = Parking_place.query.filter_by(is_occupied=1).all()
    return render_template('contracts.html', contracts=all_contracts, parking_places=all_occupied_places)


@app.route('/contracts/<int:id>')
@login_required
def detailed_contract(id):
    contract = Contract.query.get_or_404(id)
    parking_places = Parking_place.query.filter_by(contract_id=contract.id)
    tariff = Tariff.query.filter_by(id=contract.tariff_id).first()
    return render_template("contract_detail.html", contract=contract, parking_places=parking_places, tariff=tariff)


@app.route('/contracts/<int:id>/delete')
@login_required
def delete_contract(id):
    contract = Contract.query.get_or_404(id)
    user_id = contract.user_id
    parking_places = Parking_place.query.filter_by(contract_id=contract.id)
    try:
        for pp in parking_places:
            pp.is_occupied = 0
        db1.session.delete(contract)
        db1.session.commit()
        return redirect("/users/" + str(user_id))
    except:
        return "Error on deleting contract"


@app.route('/contracts/<int:id>/update_and_add', methods=['GET', 'POST'])
@login_required
def update_contract_1(id):
    current_contract = Contract.query.get_or_404(id)
    current_tariff = Tariff.query.get(current_contract.tariff_id)
    free_parking_places = Parking_place.query.filter_by(is_occupied=0).all()
    # occ_parking_places = Parking_place.query.filter_by(contract_id=current_contract.id)
    new_tariff = request.form.get('tariff_type')
    new_parking_place_id = request.form.get('parking_place_number')
    parking_place_id_to_delete = request.form.get('parking_place_number_delete')
    print(parking_place_id_to_delete)
    print(new_parking_place_id)
    if request.method == 'POST':
        if not new_parking_place_id and not parking_place_id_to_delete:
            flash('Fill all fields')
        else:
            if new_tariff == 'common':
                print(parking_place_id_to_delete)
                print(new_parking_place_id)
                current_contract.tariff_id = 1

                pp_to_add = Parking_place.query.get(new_parking_place_id)
                pp_to_add.contract_id = current_contract.id
                pp_to_add.is_occupied = 1;
                db1.session.commit()
                return redirect(url_for("detailed_contract", id=id))
            elif new_tariff == 'extended':
                current_contract.tariff_id = 2
                print(parking_place_id_to_delete)
                print(new_parking_place_id)

                pp_to_add = Parking_place.query.get(new_parking_place_id)
                pp_to_add.contract_id = current_contract.id
                pp_to_add.is_occupied = 1;
                db1.session.commit()
                return redirect(url_for("detailed_contract", id=id))
            elif new_tariff == 'premium':
                print(parking_place_id_to_delete)
                print(new_parking_place_id)
                current_contract.tariff_id = 3

                pp_to_add = Parking_place.query.get(new_parking_place_id)
                pp_to_add.contract_id = current_contract.id
                pp_to_add.is_occupied = 1;
                db1.session.commit()
                return redirect(url_for("detailed_contract", id=id))
    return render_template('contract_update.html', free_parking_places=free_parking_places,
                           current_tariff=current_tariff)


@app.route("/contracts/<int:id>/update_and_remove", methods=['GET', 'POST'])
@login_required
def update_contract_2(id):
    current_contract = Contract.query.get_or_404(id)
    occ_parking_places = Parking_place.query.filter_by(contract_id=current_contract.id)
    parking_place_id_to_delete = request.form.get('parking_place_number_delete')
    if occ_parking_places.count() == 0:
        return redirect(url_for("update_contract_1", id=current_contract.id))
    if request.method == 'POST':
        pp_to_remove = Parking_place.query.get_or_404(parking_place_id_to_delete)
        print("AAAAAAA")
        pp_to_remove.is_occupied = 0
        pp_to_remove.contract_id = null()
        db1.session.commit()
        return redirect(url_for("detailed_contract", id=current_contract.id))
    return render_template('contract_remove_pp.html', occ_parking_places=occ_parking_places)


@app.route('/create_malfunction_report', methods=['GET', 'POST'])
@login_required
@roles_required(['Worker','Admin'])
def create_malfunction_report():
    user_id = current_user.get_id()
    description = request.form.get('description')
    fix_price = request.form.get('fix_price')
    if request.method == 'POST':
        if description == '' or fix_price == '':
            flash('Please fill all fields')
            render_template('create_malfunction_report.html')
        elif float(fix_price) < 0.0:
            flash('Incorrect data in fix price field')
            render_template('create_malfunction_report.html')
        else:
            try:
                print(description)
                print(fix_price)
                new_malf_report = Malfunction(fix_price=fix_price, description=description, user_id=user_id)
                db1.session.add(new_malf_report)
                db1.session.commit()
                return redirect(url_for('detailed_user', id=user_id))
            except:
                return "Error adding report"
    return render_template('create_malfunction_report.html')


@app.route('/payed_malfunctions')
@login_required
@roles_required(['Worker', 'Admin'])
def get_payed_malfunctions():
    payed_malfunctions = Malfunction.query.filter_by(is_payed=1).all()
    return render_template('payed_malfunctions.html', payed_malfunctions=payed_malfunctions)


@app.route('/unpayed_malfunctions')
@login_required
@roles_required(['Worker', 'Admin'])
def get_unpayed_malfunctions():
    unpayed_malfunctions = Malfunction.query.filter_by(is_payed=0).all()
    return render_template('unpayed_malfunctions.html', unpayed_malfunctions=unpayed_malfunctions)


@app.route('/malfunctions')
@login_required
@roles_required(['Worker', 'Admin'])
def malfunction_routing():
    return render_template('malfunction_routing.html')


@app.route('/set_pay_price_for_clients')
@login_required
@roles_required(['Admin'])
def send_bill():
    users = Users.query.all()
    number_of_contracts = Contract.query.count()
    if not Malfunction.query.filter_by(is_payed=0).count() == 0:
        malfunction_total_fix_price = Malfunction.query.with_entities(
            func.sum(Malfunction.fix_price).label("totalSum")).filter_by(
            is_payed=0).first()
        per_contract_fix_price = float(malfunction_total_fix_price.totalSum) / number_of_contracts
    else:
        per_contract_fix_price = 0
    update = Malfunction.query.filter_by(is_payed=0).update({'is_payed': 1})
    for user in users:
        current_contract = Contract.query.filter_by(user_id=user.id).first()
        if current_contract:
            tariff = Tariff.query.filter_by(id=current_contract.tariff_id).first()
            tariff_sum = tariff.gas_tariff + tariff.electricity_tariff + tariff.water_tariff + tariff.parking_place_price
            number_of_occupied_places = Parking_place.query.filter_by(contract_id=current_contract.id).count()
            user.month_pay = per_contract_fix_price + float(number_of_occupied_places * tariff_sum)
            db1.session.commit()

        else:
            continue
    return redirect(url_for('all_users'))
