
# Tiny Second-hand Shopping Platform

Flask 기반의 중고거래 플랫폼입니다. CSRF 방지, XSS 방지, 입력 검증, 인증/인가, 비밀번호 해싱 등 웹 보안의 기본 원칙을 직접 적용하여 개발한 시큐어 코딩 실습 프로젝트입니다.

---

## 프로젝트 구조

```
secure-coding/
├── app.py                       # 메인 Flask 애플리케이션
├── templates/                   # Jinja2 HTML 템플릿
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── new_product.html
│   ├── edit_product.html
│   ├── profile.html
│   ├── report.html
│   ├── admin_report_list.html
│   ├── admin_suspended_users.html
│   ├── chat.html
│   ├── chat_list.html
│   ├── transactions.html
│   ├── transfer.html
│   ├── view_product.html
│   ├── user_profile.html
│   └── my_products.html
├── static/
│   └── style.css                # 기본 CSS 스타일
├── my_market.db                     # SQLite 데이터베이스
├── requirements.txt             # 의존성 목록
└── README.md                    # 프로젝트 설명 문서
```

---

## 개발 환경

- Python 3.10 이상
- Flask 3.1.0
- Flask-WTF (CSRF 보호)
- Flask-SocketIO
- Werkzeug (비밀번호 해싱)
- SQLite
- 운영체제: Windows 10+
- 개발 환경: venv 사용

---

## 설치 및 실행 방법

```bash
# 1. 가상환경 활성화
venv\Scripts\activate  # Windows 기준

# 2. 패키지 설치
pip install -r requirements.txt

# 3. 실행
python app.py
```

※ `app.py` 실행 시 `my_market.db` SQLite 데이터베이스가 자동 생성됩니다.

---

## 기능 구현

- 회원 가입
- 로그인
- 사용자 조회
- 마이페이지
- 실시간 전체 채팅
- 1대1 채팅
- 상품 등록
- 등록된 상품 관리
- 상품 조회
- 상품 상세 페이지
- 불량 유저 및 상품 신고
- 불량 상품 삭제
- 불량 유저 휴면
- 관리자 페이지

## 주요 보안 적용 요소

- CSRF 보호 (Flask-WTF + 토큰 삽입 및 검증)
- XSS 방지 (Jinja2 이스케이프 `|e`, 자동 escaping)
- SQL Injection 방지 (Prepared Statement 사용)
- 비밀번호 해싱 (`generate_password_hash`, `check_password_hash`)
- 입력 유효성 검증 (HTML5 속성 + 서버 정규식 검사)
- 관리자 기능 권한 제어 (세션 기반 체크)
- 파일 업로드 시 확장자 제한 및 용량 제한
- 신고 누적 시 자동 차단/휴면 처리 기능
