package test

import "os"

var Namespace = "default"
var NodeName, _ = os.Hostname()

var Label = "app=ratings,version=v1"
