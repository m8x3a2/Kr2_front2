# Практическое задание 7 — Auth + Products API

## Установка и запуск

```bash
npm install
npm start
```

Сервер запустится на `http://localhost:3000`  
Swagger UI доступен по адресу `http://localhost:3000/api-docs`

---

## Маршруты API

### Auth

| Метод | Маршрут              | Описание                        |
|-------|----------------------|---------------------------------|
| POST  | /api/auth/register   | Регистрация пользователя        |
| POST  | /api/auth/login      | Вход в систему                  |

### Products

| Метод  | Маршрут              | Описание                        |
|--------|----------------------|---------------------------------|
| POST   | /api/products        | Создать товар                   |
| GET    | /api/products        | Получить список товаров         |
| GET    | /api/products/:id    | Получить товар по id            |
| PUT    | /api/products/:id    | Обновить параметры товара       |
| DELETE | /api/products/:id    | Удалить товар                   |

---

## Примеры запросов

### Регистрация
```json
POST /api/auth/register
{
  "email": "ivan@example.com",
  "first_name": "Иван",
  "last_name": "Иванов",
  "password": "secret123"
}
```

### Вход
```json
POST /api/auth/login
{
  "email": "ivan@example.com",
  "password": "secret123"
}
```

### Создать товар
```json
POST /api/products
{
  "title": "Ноутбук",
  "category": "Электроника",
  "description": "Мощный игровой ноутбук",
  "price": 120000
}
```

---

## Сущности

### Пользователь
| Поле           | Тип    | Описание              |
|----------------|--------|-----------------------|
| id             | string | UUID (генерируется)   |
| email          | string | Логин пользователя    |
| first_name     | string | Имя                   |
| last_name      | string | Фамилия               |
| hashedPassword | string | bcrypt-хеш пароля     |

### Товар
| Поле        | Тип    | Описание            |
|-------------|--------|---------------------|
| id          | string | UUID (генерируется) |
| title       | string | Название            |
| category    | string | Категория           |
| description | string | Описание            |
| price       | number | Цена                |
