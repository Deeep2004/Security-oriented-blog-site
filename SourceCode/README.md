# Security-Sonnets
Course project of CSE418

How to use the library Redis (MacOS)

1. Check if Redis is Installed
    brew list | grep redis

2. if not installed yet:
    brew install redis

3. Start the Redis Server
    brew services start redis

4. Check Redis Status
    brew services list
    # If it replies with PONG, Redis is working.

5. Check If Redis is Listening on Port 6379
    lsof -i :6379
    # if not:
    brew services restart redis

6. if the redis not working on your local host, kindly follow the below alternative methods:

<!-- 
go to app.py

comment line 25-26, 88-91, 136-138, 236-238

uncommecnt 93-95, 140-142, 240-242 -->
