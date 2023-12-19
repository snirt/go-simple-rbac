package main

import (
	"log"
	"net"

	"google.golang.org/grpc"
)

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// create gRPC server
	server := grpc.NewServer()

	// should implement an adapter to adapt the RBAC interface to the gRPC interface

	// pb.RegisterRBACServer(server, &RBACServer{})

	if err := server.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
	
}
