from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import csv
from io import StringIO, BytesIO  
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'iso9001-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iso9001.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelos de la base de datos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # auditor, user, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, in-progress, completed
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

class AuditItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'), nullable=False)
    iso_clause = db.Column(db.String(50), nullable=False)
    requirement = db.Column(db.Text, nullable=False)
    compliance = db.Column(db.Boolean, default=False)
    comments = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.String(300), nullable=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # auditor, user, admin
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    position = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    original_filename = db.Column(db.String(300), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'), nullable=True)

class TrainingMaterial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    # Campos nuevos con valores por defecto para compatibilidad
    file_type = db.Column(db.String(50), default='pdf')
    level = db.Column(db.String(20), default='basic')
    duration = db.Column(db.String(20), nullable=True)
    filename = db.Column(db.String(300), nullable=True)
    file_url = db.Column(db.String(500), nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Función para inicializar la base de datos
def init_db():
    with app.app_context():
        db.create_all()
        
        # Verificar y agregar columnas faltantes si es necesario
        try:
            # Intentar una consulta simple para verificar si las columnas nuevas existen
            test = TrainingMaterial.query.first()
        except Exception as e:
            print("Columnas faltantes detectadas, intentando migrar...")
            # Aquí podrías agregar lógica para migrar la base de datos
            # Por simplicidad, recreamos la tabla
            TrainingMaterial.__table__.drop(db.engine)
            db.create_all()
            print("Base de datos migrada exitosamente")
        
        # Crear usuario administrador por defecto si no existe
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Usuario admin creado: admin / admin123")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Obtener datos del formulario
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        department = request.form.get('department')
        position = request.form.get('position')
        
        # Validaciones
        errors = []
        
        if not username or not email or not password:
            errors.append('Todos los campos obligatorios deben ser completados.')
        
        if password != confirm_password:
            errors.append('Las contraseñas no coinciden.')
        
        if len(password) < 6:
            errors.append('La contraseña debe tener al menos 6 caracteres.')
        
        if User.query.filter_by(username=username).first():
            errors.append('El nombre de usuario ya está en uso.')
        
        if User.query.filter_by(email=email).first():
            errors.append('El correo electrónico ya está registrado.')
        
        if errors:
            for error in errors:
                flash(error)
            return render_template('auth/register.html')
        
        # Crear nuevo usuario
        try:
            new_user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                department=department,
                position=position,
                role='user'  # Rol por defecto
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('¡Registro exitoso! Ahora puedes iniciar sesión.')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error al crear el usuario. Por favor, intenta nuevamente.')
            return render_template('auth/register.html')
    
    return render_template('auth/register.html')

@app.route('/admin/users')
@login_required
def user_management():
    # Solo administradores pueden gestionar usuarios
    if current_user.role != 'admin':
        flash('No tienes permisos para acceder a esta página.')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/toggle/<int:user_id>')
@login_required
def toggle_user_status(user_id):
    if current_user.role != 'admin':
        flash('No tienes permisos para realizar esta acción.')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    flash(f'Usuario {"activado" if user.is_active else "desactivado"} correctamente.')
    return redirect(url_for('user_management'))

@app.route('/admin/user/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('No tienes permisos para realizar esta acción.')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # No permitir eliminar el propio usuario admin
    if user.id == current_user.id:
        flash('No puedes eliminar tu propia cuenta.')
        return redirect(url_for('user_management'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash('Usuario eliminado correctamente.')
    return redirect(url_for('user_management'))



# Rutas de autenticación
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('auth/login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Estadísticas para el dashboard
    total_audits = Audit.query.count()
    completed_audits = Audit.query.filter_by(status='completed').count()
    pending_audits = Audit.query.filter_by(status='pending').count()
    audits = Audit.query.order_by(Audit.created_at.desc()).limit(5).all()
    
    return render_template('dashboard/index.html', 
                          total_audits=total_audits,
                          completed_audits=completed_audits,
                          pending_audits=pending_audits,
                          audits=audits)

@app.route('/audits')
@login_required
def audits():
    audit_list = Audit.query.all()
    return render_template('audit/list.html', audits=audit_list)

@app.route('/audit/create', methods=['GET', 'POST'])
@login_required
def create_audit():
    if request.method == 'POST':
        project_name = request.form.get('project_name')
        description = request.form.get('description')
        
        new_audit = Audit(
            project_name=project_name,
            description=description,
            created_by=current_user.id
        )
        db.session.add(new_audit)
        db.session.commit()
        
        flash('Auditoría creada exitosamente')
        return redirect(url_for('audit_detail', audit_id=new_audit.id))
    
    return render_template('audit/create.html')

@app.route('/audit/<int:audit_id>')
@login_required
def audit_detail(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    items = AuditItem.query.filter_by(audit_id=audit_id).all()
    documents = Document.query.filter_by(audit_id=audit_id).all()
    
    # Definir los requisitos ISO 9001 relevantes para software
    iso_requirements = [
        {"clause": "4.3", "requirement": "Determinación del alcance del sistema de gestión de la calidad"},
        {"clause": "5.1.1", "requirement": "Liderazgo y compromiso - Generalidades"},
        {"clause": "5.2.1", "requirement": "Establecimiento de la política de la calidad"},
        {"clause": "6.1.1", "requirement": "Acciones para abordar riesgos y oportunidades"},
        {"clause": "6.2.1", "requirement": "Objetivos de la calidad y planificación para lograrlos"},
        {"clause": "7.1.1", "requirement": "Recursos - Generalidades"},
        {"clause": "7.1.5", "requirement": "Recursos de seguimiento y medición"},
        {"clause": "7.2.1", "requirement": "Competencia"},
        {"clause": "7.3.1", "requirement": "Concienciación"},
        {"clause": "7.5.1", "requirement": "Información documentada - Generalidades"},
        {"clause": "8.1.1", "requirement": "Planificación y control operacional - Generalidades"},
        {"clause": "8.2.1", "requirement": "Requisitos para los productos y servicios"},
        {"clause": "8.3.1", "requirement": "Diseño y desarrollo de productos y servicios - Generalidades"},
        {"clause": "8.3.2", "requirement": "Planificación del diseño y desarrollo"},
        {"clause": "8.3.3", "requirement": "Entradas del diseño y desarrollo"},
        {"clause": "8.3.4", "requirement": "Controles del diseño y desarrollo"},
        {"clause": "8.3.5", "requirement": "Salidas del diseño y desarrollo"},
        {"clause": "8.3.6", "requirement": "Cambios del diseño y desarrollo"},
        {"clause": "8.5.1", "requirement": "Control de la producción y de la prestación del servicio - Generalidades"},
        {"clause": "8.5.2", "requirement": "Identificación y trazabilidad"},
        {"clause": "8.5.3", "requirement": "Propiedad perteneciente a los clientes o proveedores externos"},
        {"clause": "8.5.4", "requirement": "Preservación"},
        {"clause": "8.5.5", "requirement": "Actividades posteriores a la entrega"},
        {"clause": "8.5.6", "requirement": "Control de cambios"},
        {"clause": "8.6.1", "requirement": "Liberación de los productos y servicios - Generalidades"},
        {"clause": "8.7.1", "requirement": "Control de las salidas no conformes - Generalidades"},
        {"clause": "9.1.1", "requirement": "Seguimiento, medición, análisis y evaluación - Generalidades"},
        {"clause": "9.1.3", "requirement": "Análisis y evaluación"},
        {"clause": "9.2.1", "requirement": "Auditoría interna - Generalidades"},
        {"clause": "9.3.1", "requirement": "Revisión por la dirección - Generalidades"},
        {"clause": "10.1.1", "requirement": "Mejora - Generalidades"},
        {"clause": "10.2.1", "requirement": "No conformidad y acción correctiva - Generalidades"},
        {"clause": "10.3.1", "requirement": "Mejora continua"}
    ]
    
    # Si no hay items creados, los creamos
    if not items:
        for req in iso_requirements:
            item = AuditItem(
                audit_id=audit_id,
                iso_clause=req["clause"],
                requirement=req["requirement"]
            )
            db.session.add(item)
        db.session.commit()
        items = AuditItem.query.filter_by(audit_id=audit_id).all()
    
    return render_template('audit/detail.html', 
                          audit=audit, 
                          items=items,
                          documents=documents)

@app.route('/audit/item/update', methods=['POST'])
@login_required
def update_audit_item():
    item_id = request.form.get('item_id')
    compliance = request.form.get('compliance') == 'true'
    comments = request.form.get('comments', '')
    
    item = AuditItem.query.get_or_404(item_id)
    item.compliance = compliance
    item.comments = comments
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/audit/complete/<int:audit_id>')
@login_required
def complete_audit(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    audit.status = 'completed'
    audit.completed_at = datetime.utcnow()
    
    db.session.commit()
    
    flash('Auditoría marcada como completada')
    return redirect(url_for('audit_detail', audit_id=audit_id))

@app.route('/document/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo')
        return redirect(request.referrer)
    
    file = request.files['file']
    audit_id = request.form.get('audit_id')
    
    if file.filename == '':
        flash('No se seleccionó ningún archivo')
        return redirect(request.referrer)
    
    if file:
        # Crear directorio de uploads si no existe
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
            
        filename = secure_filename(file.filename)
        unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        new_document = Document(
            filename=unique_filename,
            original_filename=filename,
            uploaded_by=current_user.id,
            audit_id=audit_id if audit_id else None
        )
        
        db.session.add(new_document)
        db.session.commit()
        
        flash('Documento subido exitosamente')
    
    return redirect(request.referrer)

@app.route('/training')
@login_required
def training():
    materials = TrainingMaterial.query.all()
    return render_template('training/list.html', materials=materials)

@app.route('/training/upload', methods=['GET', 'POST'])
@login_required
def upload_training_material():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        file_type = request.form.get('file_type')
        level = request.form.get('level')
        
        new_material = TrainingMaterial(
            title=title,
            description=description,
            file_type=file_type,
            level=level,
            uploaded_by=current_user.id
        )
        
        if 'file' in request.files and request.files['file'].filename != '':
            file = request.files['file']
            filename = secure_filename(file.filename)
            unique_filename = f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'training', unique_filename)
            
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file.save(file_path)
            
            new_material.filename = unique_filename
        else:
            file_url = request.form.get('file_url')
            if file_url:
                new_material.file_url = file_url
        
        db.session.add(new_material)
        db.session.commit()
        
        flash('Material de capacitación agregado exitosamente')
        return redirect(url_for('training'))
    
    return render_template('training/upload.html')

@app.route('/training/material/<int:material_id>')
@login_required
def view_training_material(material_id):
    material = TrainingMaterial.query.get_or_404(material_id)
    return render_template('training/material_detail.html', material=material)

@app.route('/training/download/<int:material_id>')
@login_required
def download_training_material(material_id):
    material = TrainingMaterial.query.get_or_404(material_id)
    if material.filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'training', material.filename)
        return send_file(file_path, as_attachment=True, download_name=material.filename)
    else:
        return redirect(material.file_url)

@app.route('/reports')
@login_required
def reports():
    audits = Audit.query.all()
    return render_template('reports/list.html', audits=audits)

@app.route('/report/generate/<int:audit_id>')
@login_required
def generate_report(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    items = AuditItem.query.filter_by(audit_id=audit_id).all()
    
    # Crear CSV en memoria como bytes
    output = StringIO()
    writer = csv.writer(output)
    
    # Escribir encabezados
    writer.writerow(['Cláusula ISO', 'Requisito', 'Cumplimiento', 'Comentarios'])
    
    # Escribir datos
    for item in items:
        writer.writerow([
            item.iso_clause,
            item.requirement,
            'Sí' if item.compliance else 'No',
            item.comments or 'N/A'
        ])
    
    # Preparar respuesta - convertir a bytes
    csv_data = output.getvalue()
    csv_bytes = csv_data.encode('utf-8')
    
    # Crear BytesIO con los datos codificados
    csv_buffer = BytesIO(csv_bytes)
    csv_buffer.seek(0)
    
    # Devolver como archivo descargable
    return send_file(
        csv_buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'reporte_auditoria_{audit.project_name}.csv'
    )

if __name__ == '__main__':
    # Inicializar la base de datos
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)