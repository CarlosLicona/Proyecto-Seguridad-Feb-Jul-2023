# Generated by Django 4.2 on 2023-06-09 02:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bd', '0003_remove_usuario_id_alter_usuario_nombre_usuario'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='servicio',
            name='id',
        ),
        migrations.AlterField(
            model_name='servicio',
            name='ip',
            field=models.CharField(max_length=20, primary_key=True, serialize=False),
        ),
    ]
