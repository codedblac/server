from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import CustomUser, Address


# ----------------------
# Address Inline for User Admin
# ---------------------------
class AddressInline(admin.TabularInline):
    model = Address
    extra = 0
    readonly_fields = ["created_at", "updated_at"]
    fields = ["full_name", "phone_number", "line1", "line2", "city", "state", "postal_code", "country", "is_default", "created_at", "updated_at"]
    ordering = ["-is_default", "-created_at"]


# ---------------------------
# Custom User Admin
# ---------------------------
@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    model = CustomUser
    inlines = [AddressInline]

    list_display = ("email", "full_name", "is_staff", "is_active", "date_joined")
    list_filter = ("is_staff", "is_active")
    search_fields = ("email", "full_name")
    ordering = ("-date_joined",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("full_name",)}),
        (_("Permissions"), {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "full_name", "password1", "password2", "is_active", "is_staff", "is_superuser"),
        }),
    )


# ---------------------------
# Address Admin (Optional)
# ---------------------------
@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ("user", "full_name", "line1", "city", "postal_code", "country", "is_default", "created_at")
    list_filter = ("is_default", "country")
    search_fields = ("user__email", "full_name", "line1", "city", "postal_code")
    ordering = ("-is_default", "-created_at")
    readonly_fields = ["created_at", "updated_at"]
