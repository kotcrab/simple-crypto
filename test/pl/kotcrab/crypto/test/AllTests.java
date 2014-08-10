
package pl.kotcrab.crypto.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({CascadeCipherTest.class, SymmetricCipherTest.class, RSASignerTest.class, RSACipherTest.class})
public class AllTests {

}
