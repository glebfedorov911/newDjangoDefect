# Для страта вам потребуется Docker desktop.

# Клонируем проект.
git clone https://github.com/HAKKer5/defect-djangoDojo_translate

# Переходим в папку с проектом.
cd defect-djangoDojo_translate

# Сброка.
./dc-build.sh
# Запускаем все необходимые сервисы.
./dc-up-d.sh postgres-redis

# Получаем пароль для пользователя admin.
docker compose logs initializer | grep "Admin password:"

# Переходим по адресу 
http://localhost:8080/
