Pod::Spec.new do |s|

  s.name         = "IDZSwiftCommonCrypto"
  s.version      = "0.16.1"
  s.summary      = "A wrapper for Apple's Common Crypto library written in Swift."

  s.homepage     = "https://github.com/iosdevzone/IDZSwiftCommonCrypto"
  s.license      = "MIT"
  s.author             = { "iOSDevZone" => "idz@iosdeveloperzone.com" }
  s.social_media_url   = "http://twitter.com/iOSDevZone"
 
  s.osx.deployment_target = '10.13'
  s.ios.deployment_target = '11.0'
  s.tvos.deployment_target = '11.0'
  s.watchos.deployment_target = '5.1'

  s.source       = { :git => "https://github.com/iosdevzone/IDZSwiftCommonCrypto.git", :tag => s.version.to_s }

  s.source_files  = "IDZSwiftCommonCrypto"

  # New way to specify Swift version 
  s.swift_version = '5.0'

  s.pod_target_xcconfig = {
    "APPLICATION_EXTENSION_API_ONLY" => "YES"
  }

end
