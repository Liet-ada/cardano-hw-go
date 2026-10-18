module github.com/Liet-ada/cardano-hw-go/test/cbor-oracle

go 1.26.8

require (
	github.com/Liet-ada/cardano-hw-go v0.0.0
	github.com/fxamacker/cbor/v2 v2.9.6
)

require github.com/x448/float16 v0.8.4 // indirect

replace github.com/Liet-ada/cardano-hw-go => ../..
