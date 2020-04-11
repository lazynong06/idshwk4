### Algorithm Requirement
- In every 10 minutes check if the count of 404 response > 2
- and if the 404 ratio > 20% (404 ratio = 404 response/all response)
- and if (the unique count of url response 404 / all the count of 404 response) > 0.5
- then output " x.x.x.x is a scanner with y scan attemps on z urls" where x.x.x.x is the orig_h y is the count of 404 response, and z is the unique count of url response 404
