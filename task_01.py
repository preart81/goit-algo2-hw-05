""" 
Перевірка унікальності паролів за допомогою фільтра Блума
"""

import mmh3


class BloomFilter:
    """Реалізація структури даних фільтра Блума.

    Фільтр Блума — це ймовірнісна структура даних, яка дозволяє швидко перевіряти, чи елемент належить до певної множини.
    Фільтр Блума може дати відповідь «можливо належить» або «точно не належить». Тобто якщо фільтр Блума відповідає, що елемент не належить до множини, то це гарантовано правильно. Але якщо фільтр відповідає, що елемент належить до множини, то це може бути як правдою, так і хибним спрацюванням (false positive).
    Елементи можуть бути додані до множини, але не можуть бути видалені.

    Атрибути:
        size (int): Розмір масиву бітів.
        num_hashes (int): Кількість функцій хешування, які використовувати.
        bit_array (список): Список бітів, що представляють множину.
    """

    def __init__(self, size, num_hashes):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    def add(self, item):
        """
        Додати елемент до фільтра.

        Args:
            item: елемент, який додається до фільтра
        """

        for i in range(self.num_hashes):
            index = mmh3.hash(item, i) % self.size
            self.bit_array[index] = 1

    def contains(self, item):
        """
        Перевірити, чи є елемент у фільтрі.

        Args:
            item: елемент, який перевіряється
        Returns:
            True, якщо елемент є у фільтрі, інакше False
        """
        for i in range(self.num_hashes):
            index = mmh3.hash(item, i) % self.size
            if self.bit_array[index] == 0:
                return False
        return True


def check_password_uniqueness(bloom_filter, passwords):
    """
    Перевірити унікальність паролів за допомогою фільтра Блума.

    Args:
        bloom_filter: екземпляр BloomFilter
        passwords: список паролів для перевірки
    Returns:
        словник результатів перевірки паролів
    """
    results = {}
    for password in passwords:
        if password == "" or not isinstance(password, str):
            results[password] = "некоректний"
        else:
            if bloom_filter.contains(password):
                results[password] = "вже використаний"
            else:
                results[password] = "унікальний"
                bloom_filter.add(password)
    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")
