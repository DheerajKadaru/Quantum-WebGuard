from functools import wraps

from flask import Blueprint, redirect, session, url_for


admin_routes = Blueprint("admin_routes", __name__)


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or session.get("role") != "admin":
            return redirect(url_for("main_routes.home"))
        return view_func(*args, **kwargs)

    return wrapper


@admin_routes.route("/admin/login", methods=["GET", "POST"])
def login():
    return redirect(url_for("main_routes.home"))


@admin_routes.route("/admin/logout", methods=["POST"])
@admin_required
def logout():
    session.clear()
    return redirect(url_for("admin_routes.login"))
