package ssht_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/xchapter7x/ssht"
)

var _ = Describe("ssht", func() {
	Describe("given we have a ssht server", func() {
		Context("when created", func() {
			var startServer = func() bool {
				ssh := &ssht.SSHTestServer{
					AllowPasswordAuthN: false,
					Username:           "joe",
					Password:           "user",
					AllowKeyAuthN:      true,
					FakeResponseBytes:  []byte(`this is a test`),
					SSHCommandMatch:    "ls -lha",
				}
				ssh.Start()
				return true
			}
			It("then it should start safely", func() {
				Ω(func() { startServer() }).ShouldNot(Panic())
			})
			It("then it should not block", func() {
				Eventually(startServer).Should(BeTrue())
			})
		})

		Context("when we call close on it", func() {
			var err error
			var ssh *ssht.SSHTestServer
			BeforeEach(func() {
				ssh = &ssht.SSHTestServer{
					AllowPasswordAuthN: false,
					Username:           "joe",
					Password:           "user",
					AllowKeyAuthN:      true,
					FakeResponseBytes:  []byte(`this is a test`),
					SSHCommandMatch:    "ls -lha",
				}
				err = ssh.Start()
			})
			It("then it should close the ssh test server", func() {
				Ω(err).ShouldNot(HaveOccurred())
				Ω(ssh.Close()).ShouldNot(HaveOccurred())
				Ω(ssh.Connected).Should(BeFalse())
			})
		})

		XDescribe("given a WhenCalledWith Method", func() {
			Context("when called with a command string", func() {
				It("then it should allow us to fake the output from the given command", func() {
					Ω(true).Should(BeFalse())
				})
			})
		})

		XDescribe("given a CommandCallCount Method", func() {
			Context("when called with a command string", func() {
				It("then it should allow to see a count of the number of times the given command was called", func() {
					Ω(true).Should(BeFalse())
				})
			})
		})
	})
})
