from flask import flash, Blueprint, render_template, request
from flask_login import login_required, current_user
from .models import Note, PublicNote
from . import db
import markdown
import bleach
views = Blueprint('views',  __name__)

@views.route('/', methods =['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = bleach.clean(request.form.get('note'))

        if len(note) < 1:
            flash('Note is empty', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added', category='Success')
    data = [r.data for r in db.session.query(Note.data).filter_by(user_id = current_user.id)]
    notesMarkdown = []
    for note in data:
        note = markdown.markdown(note)
        notesMarkdown.append(note)
    return render_template("home.html",notes=notesMarkdown, user=current_user)

@views.route('/publicNotes', methods =['GET', 'POST'])
def publicNotes():
    if request.method == 'POST':
        note = bleach.clean(request.form.get('note'))

        if len(note) < 1:
            flash('Note is empty', category='error')
        else:
            new_note = PublicNote(data=note)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added', category='Success')
    data = [r.data for r in db.session.query(PublicNote.data)]
    notesMarkdown = []
    for note in data:
        note = markdown.markdown(note)
        notesMarkdown.append(note)
    return render_template("publicNotes.html", publicnote=notesMarkdown,user=current_user)