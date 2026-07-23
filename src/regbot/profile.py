"""US profile and password generation matching SAS client validation."""

from __future__ import annotations

import calendar
import random
import re
import secrets
import string
from dataclasses import dataclass
from datetime import date

# Client-side rules extracted from flysas register JS (HAR).
EMAIL_RE = re.compile(
    r"^[_a-zA-Z0-9!#$%&'*=?^_`{|}~-]+"
    r"(\.[_a-zA-Z0-9!#$%&'*=?^_`{|}~-]+)*"
    r"@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*"
    r"(\.[a-zA-Z]{2,25})$"
)
PASSWORD_RE = re.compile(
    r"(?=^.{8,50}$)"
    r"(?=.*\d)"
    r"(?=.*[a-z])"
    r"(?=.*[A-Z])"
    r"(?=.*[~!@#$%^&*_\-+=`|(){}[\]:;'\"<>,.?/\\])"
    r"(?!.*\s).*$"
)
# SAS uses \p{L}; stdlib re has no Unicode property escapes — ASCII names are enough for US profiles.
NAME_RE = re.compile(r"^[-.A-Za-z\s'_\d]{2,30}$")
OTP_RE = re.compile(r"^\d{6}$")

_FIRST_M = (
    "James", "Robert", "John", "Michael", "David", "William", "Richard", "Joseph",
    "Thomas", "Charles", "Christopher", "Daniel", "Matthew", "Anthony", "Mark", "Donald",
    "Steven", "Paul", "Andrew", "Joshua", "Kenneth", "Kevin", "Brian", "George",
    "Timothy", "Ronald", "Edward", "Jason", "Jeffrey", "Ryan", "Jacob", "Gary",
    "Nicholas", "Eric", "Jonathan", "Stephen", "Larry", "Justin", "Scott", "Brandon",
    "Benjamin", "Samuel", "Raymond", "Gregory", "Frank", "Alexander", "Patrick", "Jack",
    "Dennis", "Jerry", "Tyler", "Aaron", "Jose", "Adam", "Nathan", "Henry",
    "Douglas", "Zachary", "Peter", "Kyle", "Noah", "Ethan", "Jeremy", "Walter",
    "Christian", "Keith", "Roger", "Terry", "Austin", "Sean", "Gerald", "Carl",
    "Dylan", "Harold", "Jesse", "Bryan", "Billy", "Bruce", "Gabriel", "Joe",
    "Logan", "Alan", "Juan", "Wayne", "Roy", "Ralph", "Randy", "Eugene",
    "Vincent", "Russell", "Louis", "Philip", "Bobby", "Johnny", "Bradley", "Harry",
    "Arthur", "Albert", "Lawrence", "Roger", "Howard", "Eugene", "Carlos", "Russell",
)

_FIRST_F = (
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica",
    "Sarah", "Karen", "Lisa", "Nancy", "Betty", "Margaret", "Sandra", "Ashley",
    "Kimberly", "Emily", "Donna", "Michelle", "Dorothy", "Carol", "Amanda", "Melissa",
    "Deborah", "Stephanie", "Rebecca", "Sharon", "Laura", "Cynthia", "Kathleen", "Amy",
    "Angela", "Shirley", "Anna", "Brenda", "Pamela", "Emma", "Nicole", "Helen",
    "Samantha", "Katherine", "Christine", "Debra", "Rachel", "Carolyn", "Janet", "Catherine",
    "Maria", "Heather", "Diane", "Ruth", "Julie", "Olivia", "Joyce", "Virginia",
    "Victoria", "Kelly", "Lauren", "Christina", "Joan", "Evelyn", "Judith", "Megan",
    "Andrea", "Cheryl", "Hannah", "Jacqueline", "Martha", "Gloria", "Teresa", "Ann",
    "Sara", "Madison", "Frances", "Kathryn", "Janice", "Jean", "Abigail", "Alice",
    "Judy", "Sophia", "Grace", "Denise", "Amber", "Doris", "Marilyn", "Danielle",
    "Beverly", "Isabella", "Theresa", "Diana", "Natalie", "Brittany", "Charlotte", "Marie",
)

_FIRST = _FIRST_M + _FIRST_F
_MALE_SET = {n.lower() for n in _FIRST_M}
_FEMALE_SET = {n.lower() for n in _FIRST_F}

_LAST = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
    "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
    "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
    "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza",
    "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers",
    "Long", "Ross", "Foster", "Jimenez", "Powell", "Jenkins", "Perry", "Russell",
    "Sullivan", "Bell", "Coleman", "Butler", "Henderson", "Barnes", "Gonzales", "Fisher",
    "Vasquez", "Simmons", "Romero", "Jordan", "Patterson", "Alexander", "Hamilton", "Graham",
    "Reynolds", "Griffin", "Wallace", "Moreno", "West", "Cole", "Hayes", "Bryant",
    "Herrera", "Gibson", "Ellis", "Tran", "Medina", "Aguilar", "Stevens", "Murray",
    "Ford", "Castro", "Marshall", "Owens", "Harrison", "Fernandez", "McDonald", "Woods",
    "Washington", "Kennedy", "Wells", "Vargas", "Henry", "Chen", "Freeman", "Webb",
    "Tucker", "Guzman", "Burns", "Crawford", "Olson", "Simpson", "Porter", "Hunter",
    "Gordon", "Mendez", "Silva", "Shaw", "Snyder", "Mason", "Dixon", "Munoz",
    "Hunt", "Hicks", "Holmes", "Palmer", "Wagner", "Black", "Robertson", "Boyd",
    "Rose", "Stone", "Salazar", "Fox", "Warren", "Mills", "Meyer", "Rice",
    "Schmidt", "Garza", "Daniels", "Ferguson", "Nichols", "Stephens", "Soto", "Weaver",
    "Ryan", "Gardner", "Payne", "Grant", "Dunn", "Kelley", "Spencer", "Hawkins",
)

# Common US area codes (non-premium looking)
_AREA_CODES = (
    201, 202, 203, 205, 206, 207, 208, 209, 210, 212, 213, 214, 215, 216, 217,
    218, 219, 224, 225, 228, 229, 231, 234, 239, 240, 248, 251, 252, 253, 254,
    256, 260, 262, 267, 269, 270, 272, 276, 281, 301, 302, 303, 304, 305, 307,
    308, 309, 310, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 323, 325,
    330, 331, 334, 336, 337, 339, 346, 347, 351, 352, 360, 361, 364, 380, 385,
    386, 401, 402, 404, 405, 406, 407, 408, 409, 410, 412, 413, 414, 415, 417,
    419, 423, 424, 425, 430, 432, 434, 435, 440, 442, 443, 445, 458, 463, 469,
    470, 475, 478, 479, 480, 484, 501, 502, 503, 504, 505, 507, 508, 509, 510,
    512, 513, 515, 516, 517, 518, 520, 530, 531, 534, 539, 540, 541, 551, 559,
    561, 562, 563, 564, 567, 570, 571, 573, 574, 575, 580, 585, 586, 601, 602,
    603, 605, 606, 607, 608, 609, 610, 612, 614, 615, 616, 617, 618, 619, 620,
    623, 626, 628, 629, 630, 631, 636, 641, 646, 650, 651, 657, 660, 661, 662,
    667, 669, 678, 681, 682, 701, 702, 703, 704, 706, 707, 708, 712, 713, 714,
    715, 716, 717, 718, 719, 720, 724, 725, 727, 730, 731, 732, 734, 737, 740,
    743, 747, 754, 757, 760, 762, 763, 765, 769, 770, 772, 773, 774, 775, 779,
    781, 785, 786, 801, 802, 803, 804, 805, 806, 808, 810, 812, 813, 814, 815,
    816, 817, 818, 828, 830, 831, 832, 843, 845, 847, 848, 850, 856, 857, 858,
    859, 860, 862, 863, 864, 865, 870, 872, 878, 901, 903, 904, 906, 907, 908,
    909, 910, 912, 913, 914, 915, 916, 917, 918, 919, 920, 925, 928, 929, 930,
    931, 934, 936, 937, 938, 940, 941, 947, 949, 951, 952, 954, 956, 959, 970,
    971, 972, 973, 978, 979, 980, 984, 985, 989,
)

_SPECIALS = "~!@#$%^&*_-+="


@dataclass(frozen=True)
class UsProfile:
    first_name: str
    last_name: str
    gender: str  # "m" | "f"
    date_of_birth: str  # YYYY-MM-DD
    phone: str  # +1...
    password: str
    country_name: str = "United States"
    country_code: str = "US"

    def enrollment_address(self, email: str) -> dict:
        return {
            "physical": [
                {
                    "id": 0,
                    "addressLine1": "",
                    "category": "Home",
                    "city": {"name": ""},
                    "country": {"name": self.country_name, "code": self.country_code},
                    "zipCode": "",
                }
            ],
            "virtual": {
                "email": [{"id": 1, "category": "Home", "emailAddress": email}],
                "mobile": [{"id": 0, "category": "Home", "phoneNumber": self.phone}],
            },
        }


def generate_password(length: int = 14) -> str:
    """Generate a password that satisfies SAS PASSWORD_RE."""
    if length < 8 or length > 50:
        raise ValueError("password length must be 8-50")
    # Guarantee character classes, fill rest randomly.
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(_SPECIALS),
    ]
    alphabet = string.ascii_letters + string.digits + _SPECIALS
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + rest
    # Shuffle without introducing spaces
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    password = "".join(chars)
    if not PASSWORD_RE.match(password):
        # Extremely unlikely; recurse once
        return generate_password(length)
    return password


def generate_us_phone(*, rng: random.Random | None = None) -> str:
    r = rng or random
    area = r.choice(_AREA_CODES)
    # Exchange cannot start with 0 or 1 in NANP
    exchange = r.randint(200, 999)
    subscriber = r.randint(0, 9999)
    return f"+1{area}{exchange}{subscriber:04d}"


def _title_name(token: str) -> str:
    """Title-case a name token while keeping short particles sensible."""
    token = token.strip("._- ")
    if not token:
        return ""
    lower = token.lower()
    if lower.startswith("mc") and len(lower) > 3:
        return "Mc" + lower[2:].capitalize()
    if lower.startswith("o'") and len(lower) > 2:
        return "O'" + lower[2:].capitalize()
    if "-" in lower:
        return "-".join(p.capitalize() for p in lower.split("-") if p)
    return lower.capitalize()


def _clean_name_token(raw: str) -> str:
    """Strip digits/noise from an email local-part fragment."""
    cleaned = re.sub(r"\d+", "", raw)
    cleaned = re.sub(r"[^A-Za-z'\-]", "", cleaned)
    return _title_name(cleaned)


def names_from_email(email: str) -> tuple[str, str] | None:
    """Infer first/last from local part when it looks like first.last[digits].

    Examples:
      harry.musky275@slmails.com → (Harry, Musky)
      ronald.bush900@x.com → (Ronald, Bush)
    """
    local = email.split("@", 1)[0].strip().lower()
    if not local:
        return None
    parts = [p for p in re.split(r"[._+\-]+", local) if p]
    if len(parts) < 2:
        return None
    alpha_parts = [p for p in parts if re.search(r"[a-zA-Z]", p)]
    if len(alpha_parts) < 2:
        return None
    first = _clean_name_token(alpha_parts[0])
    last = _clean_name_token(alpha_parts[-1])
    if not first or not last or first.lower() == last.lower():
        return None
    if len(first) < 2 or len(last) < 2:
        return None
    if not NAME_RE.match(first) or not NAME_RE.match(last):
        return None
    return first, last


def gender_for_first_name(first: str, *, rng: random.Random | None = None) -> str:
    r = rng or random
    key = first.strip().lower()
    if key in _MALE_SET and key not in _FEMALE_SET:
        return "m"
    if key in _FEMALE_SET and key not in _MALE_SET:
        return "f"
    return r.choice(("m", "f"))


def generate_dob(
    *,
    rng: random.Random | None = None,
    min_age: int = 25,
    max_age: int = 58,
) -> str:
    """Realistic adult DOB: valid calendar day, age band weighted toward ~34."""
    r = rng or random
    today = date.today()
    age = int(r.triangular(min_age, max_age, 34))
    year = today.year - age
    month = r.randint(1, 12)
    day = r.randint(1, calendar.monthrange(year, month)[1])
    candidate = date(year, month, day)

    def age_on(d: date) -> int:
        return today.year - d.year - ((today.month, today.day) < (d.month, d.day))

    while age_on(candidate) < min_age:
        year -= 1
        day = min(day, calendar.monthrange(year, month)[1])
        candidate = date(year, month, day)
    while age_on(candidate) > max_age:
        year += 1
        day = min(day, calendar.monthrange(year, month)[1])
        candidate = date(year, month, day)
    return candidate.isoformat()


def generate_us_profile(
    *,
    rng: random.Random | None = None,
    email: str | None = None,
) -> UsProfile:
    """Generate a coherent US profile; prefers names inferred from ``email``."""
    r = rng or random.Random()
    inferred = names_from_email(email) if email else None
    if inferred:
        first, last = inferred
        gender = gender_for_first_name(first, rng=r)
    else:
        gender = r.choice(("m", "f"))
        first = r.choice(_FIRST_M if gender == "m" else _FIRST_F)
        last = r.choice(_LAST)
    profile = UsProfile(
        first_name=first,
        last_name=last,
        gender=gender,
        date_of_birth=generate_dob(rng=r),
        phone=generate_us_phone(rng=r),
        password=generate_password(),
    )
    if not NAME_RE.match(profile.first_name) or not NAME_RE.match(profile.last_name):
        return generate_us_profile(rng=r, email=None)
    return profile


def build_us_profile(
    *,
    first_name: str | None = None,
    last_name: str | None = None,
    gender: str | None = None,
    date_of_birth: str | None = None,
    phone: str | None = None,
    password: str | None = None,
    email: str | None = None,
) -> UsProfile:
    """Build a US profile, filling any omitted fields with generated values."""
    base = generate_us_profile(email=email)
    first = (first_name or base.first_name).strip()
    last = (last_name or base.last_name).strip()
    if gender is None:
        g = gender_for_first_name(first) if first_name else base.gender
    else:
        g = gender.strip().lower()
        if g in {"male", "m", "mr"}:
            g = "m"
        elif g in {"female", "f", "ms", "mrs"}:
            g = "f"
        elif g not in {"m", "f"}:
            raise ValueError(f"gender must be m/f, got {gender!r}")
    pwd = password or base.password
    if not PASSWORD_RE.match(pwd):
        raise ValueError("password does not meet SAS rules (8-50, upper, lower, digit, special)")
    if not NAME_RE.match(first) or not NAME_RE.match(last):
        raise ValueError("first/last name must be 2-30 letters (SAS name rule)")
    return UsProfile(
        first_name=first,
        last_name=last,
        gender=g,
        date_of_birth=(date_of_birth or base.date_of_birth).strip(),
        phone=(phone or base.phone).strip(),
        password=pwd,
    )


def validate_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email))
