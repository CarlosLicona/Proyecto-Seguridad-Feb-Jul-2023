# Generated by Django 4.1.2 on 2022-12-21 05:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bd', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Usuario',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nombre_usuario', models.CharField(max_length=30)),
                ('contraseña', models.CharField(max_length=30)),
            ],
        ),
        migrations.DeleteModel(
            name='Autor',
        ),
    ]