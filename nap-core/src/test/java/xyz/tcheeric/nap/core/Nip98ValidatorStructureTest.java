package xyz.tcheeric.nap.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Structural guard over {@code Nip98Validator.verifyNip98Completion}.
 *
 * <p>CodeQL's {@code java/user-controlled-bypass} rule flags the early returns in that method,
 * because each is a branch on attacker-controlled input that decides whether signature
 * verification runs. Those alerts were dismissed as false positives on one specific ground:
 * every early return produces a {@code failure}, so a caller choosing the branch chooses which
 * rejection they receive and never whether verification happens.
 *
 * <p>That is a claim about shape, and a dismissed alert does not re-open itself when the shape
 * changes. A future guard clause that returns {@code success} early, say a fast path for a
 * cached or pre-validated header, would make the original alert correct again and silently
 * inherit the dismissal. This test is what turns the reasoning behind that dismissal into
 * something enforced.
 *
 * <p>It reads the source rather than exercising behaviour because the property is structural:
 * "there is exactly one success return, and signature verification precedes it" is not
 * observable from any single call. The behavioural cases live in {@link Nip98ValidatorTest},
 * including a tampered signature being refused.
 */
class Nip98ValidatorStructureTest {

    private static final Path SOURCE = Path.of(
            "src/main/java/xyz/tcheeric/nap/core/Nip98Validator.java");

    /**
     * The body of {@code verifyNip98Completion}, from its signature to the first line that is
     * flush against the class indent, which is where the next member begins.
     */
    private static List<String> methodBody() throws IOException {
        List<String> lines = Files.readAllLines(SOURCE);
        List<String> body = new ArrayList<>();
        boolean inMethod = false;
        for (String line : lines) {
            if (line.contains("public static Nip98ValidationResult verifyNip98Completion(")) {
                inMethod = true;
                continue;
            }
            if (inMethod) {
                if (line.equals("    }")) {
                    break;
                }
                body.add(line);
            }
        }
        assertThat(inMethod)
                .as("verifyNip98Completion not found in %s: this test is stale", SOURCE)
                .isTrue();
        assertThat(body).as("method body parsed as empty").isNotEmpty();
        return body;
    }

    @Test
    @DisplayName("every early return is a failure: exactly one success return exists")
    void onlyOneSuccessReturn() throws IOException {
        List<String> successReturns = methodBody().stream()
                .filter(line -> line.contains("return Nip98ValidationResult.success("))
                .toList();

        assertThat(successReturns)
                .as("A second success return would mean a caller-controlled branch can reach "
                        + "an authenticated result without passing every check. That is the "
                        + "condition the dismissed CodeQL alerts assumed was impossible.")
                .hasSize(1);
    }

    @Test
    @DisplayName("signature verification precedes the success return")
    void signatureIsVerifiedBeforeSuccess() throws IOException {
        List<String> body = methodBody();

        int verifyAt = -1;
        int successAt = -1;
        for (int i = 0; i < body.size(); i++) {
            String line = body.get(i);
            if (verifyAt < 0 && line.contains("verifySignature(event)")) {
                verifyAt = i;
            }
            if (successAt < 0 && line.contains("return Nip98ValidationResult.success(")) {
                successAt = i;
            }
        }

        assertThat(verifyAt).as("verifySignature(event) call not found").isNotNegative();
        assertThat(successAt).as("success return not found").isNotNegative();
        assertThat(verifyAt)
                .as("Signature verification must precede the only success return, otherwise an "
                        + "unsigned or forged event can be accepted.")
                .isLessThan(successAt);
    }
}
