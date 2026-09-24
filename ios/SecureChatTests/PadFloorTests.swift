import CryptoKit
import XCTest
@testable import SecureChat

/// The floor's contract (PadFloor.kt / PadFloor.swift): monotone, no lowering,
/// forged or corrupted records fail closed, and a record cannot move ids.
final class PadFloorTests: XCTestCase {
    private var file: URL!
    private var key: SymmetricKey!
    private var floor: PadFloor!

    override func setUp() {
        super.setUp()
        file = FileManager.default.temporaryDirectory.appendingPathComponent("floor-\(UUID().uuidString).json")
        key = SymmetricKey(size: .bits256)
        let k = key!
        floor = PadFloor(fileURL: file, keyProvider: { k })
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: file)
        super.tearDown()
    }

    func testAbsentThenMonotone() {
        XCTAssertEqual(floor.read("p1"), PadFloor.absent)
        XCTAssertEqual(floor.bump("p1", 5), 5)
        XCTAssertEqual(floor.bump("p1", 3), 5, "never lowers")
        XCTAssertEqual(floor.bump("p1", -1), 5, "negative is a read")
        XCTAssertEqual(floor.bump("p1", 9), 9)
        XCTAssertEqual(floor.read("p1"), 9)
        XCTAssertEqual(floor.read("p2"), PadFloor.absent)
        XCTAssertEqual(floor.bump("p2", 0), 0, "a floor of 0 is distinct from absent")
        XCTAssertEqual(floor.read("p2"), 0)
    }

    func testEditedValueIsTamperedAndNotHealed() throws {
        XCTAssertEqual(floor.bump("p1", 7), 7)
        var dict = try records()
        let tag = dict["p1"]!.split(separator: ":", maxSplits: 1)[1]
        dict["p1"] = "2:\(tag)"                       // rewind, keep the old tag
        try write(dict)
        XCTAssertEqual(floor.read("p1"), PadFloor.tampered)
        XCTAssertEqual(floor.bump("p1", 100), PadFloor.tampered, "a forged record must not be healed")
        XCTAssertEqual(try records()["p1"], "2:\(tag)", "nothing written")
    }

    func testRecordCannotMoveIds() throws {
        XCTAssertEqual(floor.bump("recv:aa", 3), 3)
        var dict = try records()
        dict["aa"] = dict["recv:aa"]
        try write(dict)
        XCTAssertEqual(floor.read("aa"), PadFloor.tampered)
    }

    func testDifferentKeyIsTampered() {
        XCTAssertEqual(floor.bump("p1", 4), 4)
        let other = PadFloor(fileURL: file, keyProvider: { SymmetricKey(size: .bits256) })
        XCTAssertEqual(other.read("p1"), PadFloor.tampered)
        let noKey = PadFloor(fileURL: file, keyProvider: { nil })
        XCTAssertEqual(noKey.read("p1"), PadFloor.tampered)
        XCTAssertEqual(noKey.read("never-set"), PadFloor.absent)
    }

    func testCorruptFileFailsClosedForEveryId() throws {
        XCTAssertEqual(floor.bump("p1", 4), 4)
        try Data("{not json".utf8).write(to: file)
        XCTAssertEqual(floor.read("p1"), PadFloor.tampered)
        XCTAssertEqual(floor.read("other"), PadFloor.tampered)
        XCTAssertEqual(floor.bump("other", 1), PadFloor.tampered)
        XCTAssertEqual(try String(contentsOf: file), "{not json")
    }

    func testMalformedRecordShapes() throws {
        for raw in [":abc", "abc", "-1:AAAA", "1e3:AAAA", " 5:AAAA", "5:not-base64!"] {
            try write(["x": raw])
            XCTAssertEqual(floor.read("x"), PadFloor.tampered, raw)
        }
    }

    func testDeletedFileReadsAbsent() {
        XCTAssertEqual(floor.bump("p1", 4), 4)
        try? FileManager.default.removeItem(at: file)
        // Destruction is not rewinding: the client treats ABSENT-where-expected
        // as tampering (nativeFloor flag inside the pad's AEAD).
        XCTAssertEqual(floor.read("p1"), PadFloor.absent)
    }

    func testFileIsExcludedFromBackup() throws {
        XCTAssertEqual(floor.bump("p1", 1), 1)
        let values = try file.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }

    func testKeychainKeyIsStable() {
        let a = PadFloor.keychainKey()
        let b = PadFloor.keychainKey()
        XCTAssertNotNil(a)
        XCTAssertEqual(a.map { $0.withUnsafeBytes { Data($0) } }, b.map { $0.withUnsafeBytes { Data($0) } })
    }

    private func records() throws -> [String: String] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: String]
    }

    private func write(_ dict: [String: String]) throws {
        try JSONSerialization.data(withJSONObject: dict).write(to: file)
    }
}
