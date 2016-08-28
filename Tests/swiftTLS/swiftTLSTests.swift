import XCTest
@testable import swiftTLS

class swiftTLSTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(swiftTLS().text, "Hello, World!")
    }


    static var allTests : [(String, (swiftTLSTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
