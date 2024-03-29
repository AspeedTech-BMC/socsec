from socsec import __version__
import setuptools

setuptools.setup(
        name="socsec",
        version=__version__,
        author="ASPEED Technology",
        author_email="bmc-sw@aspeedtech.com",
        description="Secure-boot utilities for ASPEED BMC SoCs",
        url="https://github.com/AspeedTech-BMC/socsec/",
        packages=setuptools.find_packages(),
        scripts=['tools/socsec', 'tools/otptool'],
        package_data={'socsec': ['otp_info/*']}
)
