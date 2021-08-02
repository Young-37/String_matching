# String_matching
KMP, Boyer-Moore 을 활용하여 프로그램 내 악성코드 패턴 탐지

### Input: 15개 이상의 프로그램 코드, 악성코드, 악성코드에 대한 패턴의 길이
- 프로그램 코드는 txt파일 형식으로 받음
- 프로그램 코드와 악성코드는 숫자, 영어, 특수문자(#, !, @등)로 구성됨
- 하나의 프로그램 코드: 27개 이상의 문자들
- 악성코드: 12개 이상의 문자들
- ex. 악성코드 = abcd123!@, 악성코드 패턴의 길이 = 4 -> 악성코드 패턴 = [abcd, bcd1, cd12, ...]

### Output: 바이러스 패턴을 가진 프로그램 이름 및 개수, 바이러스 패턴을 가지지 않은 프로그램 이름 및 개수, 각 알고리즘(KMP, BM)의 총 실행시간
<br><br>
*프로그램 실행 예시
![image](https://user-images.githubusercontent.com/67675422/127845499-202c04f2-63a6-42d4-9716-012a3a2b183b.png)

<br><br>
programcode: 예시 프로그램 코드
.exe: 실행파일
