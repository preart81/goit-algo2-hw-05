""" 
Порівняння продуктивності HyperLogLog із точним підрахунком унікальних елементів
"""

import math
import re
import time

import mmh3
from rich.console import Console
from rich.table import Table


class HyperLogLog:
    """Клас HyperLogLog для приблизного підрахунку унікальних елементів.

    HyperLogLog - це алгоритм, який використовується для оцінки кількості унікальних елементів у великому обсязі даних із дуже малим використанням пам’яті.
    Цей алгоритм також належить до наближених алгоритмів (approximation algorithms), які дозволяють отримати результат з певною похибкою, але значно економлять ресурси.

    Args:
        p (int): визначає точність алгоритму. Більше значення p підвищує точність, але збільшує використання пам'яті.
    """

    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        # Змінна registers розміром 2**p — кількість регістрів. Кожен регістр зберігає максимальне значення кількості провідних нулів.
        self.registers = [0] * self.m
        # alpha — константа нормалізації, яка корегує систематичну похибку оцінки.
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2  # Поріг для малих значень

    def _get_alpha(self):
        """Метод  обчислює константу нормалізації залежно від кількості регістрів.

        Ці значення були емпірично визначені для оптимізації точності алгоритму.
        """
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        """Ключовий метод для роботи алгоритму HyperLogLog:

        1. Елемент хешується за допомогою MurmurHash3.
        2. Перші p бітів хешу визначають індекс регістра j.
        3. Решта бітів w використовується для обчислення кількості провідних нулів.
        4. Регістр оновлюється максимальним значенням.

        """
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        """Обчислює кількість провідних нулів у бінарному представленні числа.

        Це ключова операція для оцінки кардинальності.
        """
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        """Оцінює кардинальність множини.

        Він обчислює середнє гармонійне значень регістрів Z.
        Застосовується формула оцінки з нормалізацією E. Сам результат корегується для зменшення систематичної похибки.
        """
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def get_ip_from_string(string: str) -> str:
    """Метод отримання IP-адреси з рядка"""
    # Шаблон для пошуку IP-адреси
    ip_regexp = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    ip = ip_regexp.search(string).group()
    return ip


# Метод завантаження даних обробляє лог-файл, ігноруючи некоректні рядки
def load_ip(file_name: str) -> list:
    """Метод завантаження даних з файлу
    Returns:
        list: Список IP-адрес
    """
    ip_list = []
    with open(file_name, "r") as file:
        for line in file:
            try:
                ip = get_ip_from_string(line)
                ip_list.append(ip)
            except Exception as e:
                print(f"Error processing line: {e}")
                continue

    return ip_list


# Метод завантаження даних обробляє лог-файл, ігноруючи некоректні рядки. Результат не містить дублікатів
def load_ip_unique(file_name: str) -> set:
    """Метод завантаження даних з файлу без дублікатів
    Returns:
        set: Множина унікальних IP-адрес
    """
    ip_set = set()
    with open(file_name, "r") as file:
        for line in file:
            try:
                ip = get_ip_from_string(line)
                ip_set.add(ip)
            except Exception as e:
                print(f"Error processing line: {e}")
                continue

    return ip_set


if __name__ == "__main__":
    # Завантаження даних
    # ip_set = load_ip_unique("lms-stage-access.log")
    ip_list = load_ip("lms-stage-access.log")

    # Виведення перших 10 елементів з data:set()
    # pprint(sorted(list(ip_list)))

    # Підрахунок унікальних елементів за допомогою структури set.
    start = time.time()
    exact_count = len(set(ip_list))
    exact_time = time.time() - start
    # print(f"{exact_time = }")

    # Підрахунок унікальних елементів за допомогою HyperLogLog
    hll = HyperLogLog()

    start = time.time()
    for ip in ip_list:
        hll.add(ip)
    hll_count = hll.count()
    hll_time = time.time() - start

    # Виведення таблиці порівння результатів
    print("\n")
    table = Table(
        title="Порівняння продуктивності HyperLogLog із точним підрахунком унікальних елементів"
    )

    table.add_column("Метод", justify="center", )
    table.add_column("Унікальні елементи", justify="right")
    table.add_column("Час виконання (сек.)", justify="right")

    table.add_row("Точний підрахунок", f"{exact_count:,}", f"{exact_time:.16f}")
    table.add_row("HyperLogLog", f"{hll_count:,}", f"{hll_time:.16f}")

    console = Console()
    console.print(table)
