# get SQLite Table Schema
# SELECT sql FROM sqlite_master WHERE type='table' AND name='mytable'
CREATE TABLE `passes` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `user_id` integer REFERENCES `users` ON DELETE CASCADE ON UPDATE CASCADE, `serial_number` varchar(255), `authentication_token` varchar(255), `pass_type_id` varchar(255), `created_at` timestamp, `updated_at` timestamp)

# DB Schema
CREATE TABLE `passes` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `user_id` integer REFERENCES `users` ON DELETE CASCADE ON UPDATE CASCADE, `serial_number` varchar(255), `authentication_token` varchar(255), `pass_type_id` varchar(255), `created_at` timestamp, `updated_at` timestamp);
CREATE TABLE `registrations` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `uuid` varchar(255), `device_id` varchar(255), `push_token` varchar(255), `serial_number` varchar(255), `pass_type_id` varchar(255), `created_at` timestamp, `updated_at` timestamp);
CREATE TABLE `users` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `email` varchar(255), `name` varchar(255), `account_balance` double precision, `created_at` timestamp, `updated_at` timestamp);
