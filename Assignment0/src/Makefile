CXX_SERVER_SRCS = server.c
CXX_SERVER_OBJS = $(CXX_SERVER_SRCS:%.c=%.o)

CXX_CLIENT_SRCS = client.c 
CXX_CLIENT_OBJS = $(CXX_CLIENT_SRCS:%.c=%.o)

CXX_BINARY_SRCS = binary_converter.c
CXX_BINARY_OBJS = $(CXX_BINARY_SRCS:%.c=%.o)


CXX = gcc
CXXFLAGS = 

%.o : %.c
	$(CXX) $(CXXFLAGS) -c $<

client: $(CXX_CLIENT_OBJS)
	$(CXX) -o $@ $(CXX_CLIENT_OBJS)

server: $(CXX_SERVER_OBJS)
	$(CXX) -o $@ $(CXX_SERVER_OBJS)

binary: $(CXX_BINARY_OBJS)
	$(CXX) -o $@ $(CXX_BINARY_OBJS)

clean:
	rm -f *.o client server binary
