const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const app = express();
const port = process.env.PORT || 3000;

// dotenv를 사용하여 .env 파일의 내용을 process.env에 로드합니다.


// MySQL Database Configuration
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '0000',
  database: 'pi'
};

// MySQL Connection Pool
const pool = mysql.createPool(dbConfig);

// 미들웨어 등록
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// 정적 파일 서비스 (styles.css, frontend.js 등)
app.use(express.static(__dirname));

// 메인 페이지 라우트
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/var/www/html/index.html');
});

// 로그인 페이지 라우트
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/var/www/html/login.html');
});

// 회원가입 페이지 라우트
app.get('/signup', (req, res) => {
  res.sendFile(__dirname + '/var/www/html/signup.html');
});

// 로그인 요청 처리
app.post('/login', async (req, res) => {
  // 클라이언트가 보낸 요청에서 사용자명(username)과 비밀번호(password)를 추출합니다.
  const { username, password } = req.body;

  try {
    // 데이터베이스에서 해당 사용자 정보 가져오기
    pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username],
      async (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).json({ message: 'Login failed.' });
        } else if (result.length === 0) {
          res.status(404).json({ message: 'User not found.' });
        } else {
          const user = result[0];

          // 비밀번호 해시화 비교
          const isPasswordMatched = await bcrypt.compare(password, user.password);

          if (isPasswordMatched) {
            res.status(200).json({ message: 'Login successful!' });
          } else {
            res.status(401).json({ message: 'Invalid password.' });
          }
        }
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Login failed.' });
  }
});

// 회원가입 요청 처리
app.post('/signup', async (req, res) => {
  // 클라이언트가 보낸 요청에서 사용자명(username)과 비밀번호(password)를 추출합니다.
  const { username, password } = req.body;

  try {
    // 비밀번호 해시화
    const hashedPassword = await bcrypt.hash(password, 10);

    // 사용자 정보 데이터베이스에 저장
    pool.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).json({ message: 'Signup failed.' });
        } else {
          res.status(201).json({ message: 'Signup successful!' });
        }
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Signup failed.' });
  }
});

// 서버 시작
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
