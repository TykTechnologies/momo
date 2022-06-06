# MoMo
Momo is a multi-vendor Gateway Management server for Tyk Dashboard, momo will atempt to translate your API definitions and tokens to configure third-party proxies.

[Watch a video of it in action here](https://www.youtube.com/watch?v=yTPRPb51bm0)

## Quickstart

Compile Momo with `go build`

Create a `momo.conf` file:

```azure
{
  "Momo": {
    "StorageTag": "momo",
    "StoreType": "Mongo",
    "TykAPITag": "primary",
    "Drivers": {
      "AWS": {
        "Conf": {
          "KeyID": "AWSKEY",
          "Secret": "AWSSECRET",
          "Region": "us-east-1"

        }
      }
    }
  },
  "MongoStore": {
    "momo": {
      "ConnStr":      "mongodb://0.0.0.0:27017",
      "ControllerDb": "momo"
    }
  },
  "TykAPI": {
    "primary": {
      "DashboardEndpoint": "http://localhost:3000",
      "Secret": "DASHBOARD_KEY",
      "AvailabilityTests": "1",
      "AvailabilityWait": 3,
      "Mock": false
    }
  }
}
```

Open your Tyk Dashboard and create an API, and make sure to tag it with `amazon-api-gateway`. You can also push tokens tagged in the same way.

### This is a lab project and therefore unsupported

