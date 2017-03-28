{
  'targets': [
    {
      'target_name': 'node-capture',
      'sources': [
        'src/binding.cc',
      ],
      'include_dirs': [
        "<!(node -e \"require('nan')\")",
      ],
      'conditions': [
        [ 'OS=="win"', {
          'include_dirs': [
            'deps/npcap-sdk/Include',
          ],
          'defines': [
            'WPCAP', 'WIN32', '_WIN32'
          ],
          'conditions': [
            [ 'target_arch=="ia32"', {
              'link_settings': {
                'libraries': ['ws2_32.lib', '<(PRODUCT_DIR)/../../deps/npcap-sdk/Lib/wpcap.lib'],
              },
            }, {
              'link_settings': {
                'libraries': ['ws2_32.lib', '<(PRODUCT_DIR)/../../deps/npcap-sdk/Lib/x64/wpcap.lib'],
              },
            }],
          ],
        }, {
          # POSIX
          'link_settings': {
            'libraries': ['-lpcap'],
          },
        }],
      ],
    },
  ],
}